/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/jump_label.h>

#include "compat/jailbreak.h"
#include "infra/symbol_resolver.h"
#include "klog.h"

DEFINE_STATIC_KEY_FALSE(ksu_rkp_key);

void rkp_jb_init(void)
{
    if (find_kernel_symbol_exact("rkp_started")) {
        static_branch_enable(&ksu_rkp_key);
        pr_info("Samsung RKP detected\n");
    }
}

#ifdef __aarch64__

#include <linux/moduleloader.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/set_memory.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
#include <linux/execmem.h>
#define ksu_exec_alloc(sz) execmem_alloc(EXECMEM_MODULE_TEXT, (sz))
#define ksu_exec_free(p) execmem_free(p)
#else
#define ksu_exec_alloc(sz) module_alloc(sz)
#define ksu_exec_free(p) vfree(p)
#endif
#include "hook/patch_memory.h"

struct ksu_branch_site {
    void *fn_addr;
    u32 displaced_insn;
    int stub_idx;
    int preamble_skip;
};

#define KSU_MAX_BRANCH_SITES 16
/* Stub layout: [kcfi_hash][displaced_insn][B fn+N][pad]
 * Callable entry is stub+4; KCFI reads (entry-4) = stub[0] = kcfi_hash.
 * N = (preamble_skip + 1) * 4, i.e. resume after the patched branch. */
#define KSU_STUB_SIZE 16

static struct ksu_branch_site ksu_sites[KSU_MAX_BRANCH_SITES];
static int ksu_site_count;
static DEFINE_MUTEX(ksu_site_lock);
static void *ksu_stub_page;
static int ksu_stub_next;

static u32 ksu_encode_b(void *from, void *to)
{
    s64 imm26 = ((s64)(unsigned long)to - (s64)(unsigned long)from) >> 2;

    if (imm26 < -(1 << 25) || imm26 > (1 << 25) - 1)
        return 0;
    return 0x14000000u | (u32)(imm26 & 0x3FFFFFFu);
}

static bool ksu_insn_is_bti_landing_pad(u32 insn)
{
    /* BTI variants: bits[31:8]=0xD50324, bit5=0 (op2 even), bits[4:0]=0x1F */
    if ((insn & 0xFFFFFF3F) == 0xD503241F)
        return true;
    /* PACIASP */
    if (insn == 0xD503233F)
        return true;
    /* PACIBSP */
    if (insn == 0xD503237F)
        return true;
    return false;
}

static bool ksu_insn_is_pc_relative(u32 insn)
{
    return ((insn & 0x1F000000u) == 0x10000000u) || /* ADR/ADRP */
           ((insn & 0x3B000000u) == 0x18000000u) || /* LDR literal */
           ((insn & 0x7C000000u) == 0x14000000u) || /* B / BL */
           ((insn & 0xFE000000u) == 0x54000000u) || /* B.cond / BC.cond */
           ((insn & 0x7E000000u) == 0x34000000u) || /* CBZ / CBNZ */
           ((insn & 0x7E000000u) == 0x36000000u); /* TBZ / TBNZ */
}

static struct ksu_branch_site *ksu_find_site(void *fn)
{
    int i;

    for (i = 0; i < ksu_site_count; i++)
        if (ksu_sites[i].fn_addr == fn)
            return &ksu_sites[i];
    return NULL;
}

int ksu_rkp_branch_patch(void *dst, void *src)
{
    void *current_fn, *new_fn;
    struct ksu_branch_site *site;
    u32 displaced_insn, branch_b;
    int ret, stub_idx;
    void *stub;
    u32 stub_insns[2];

    current_fn = *(void **)dst;
    new_fn = *(void **)src;

    mutex_lock(&ksu_site_lock);

    site = ksu_find_site(current_fn);
    if (site) {
        /* Restore: write back the displaced instruction at the patched offset. */
        void *restore_addr = (u8 *)current_fn + site->preamble_skip * 4;
        displaced_insn = site->displaced_insn;
        ret = aarch64_insn_patch_text(&restore_addr, &displaced_insn, 1);
        if (ret) {
            mutex_unlock(&ksu_site_lock);
            pr_err("ksu: branch site restore failed at %pS: %d\n", current_fn, ret);
            return ret;
        }
        *site = ksu_sites[--ksu_site_count];
        pr_info("ksu: branch site removed at %pS\n", current_fn);
        if (new_fn == current_fn) {
            mutex_unlock(&ksu_site_lock);
            return 0;
        }
    }

    if (current_fn == new_fn) {
        mutex_unlock(&ksu_site_lock);
        return 0;
    }

    if (ksu_site_count >= KSU_MAX_BRANCH_SITES) {
        mutex_unlock(&ksu_site_lock);
        pr_err("ksu: branch site table full\n");
        return -ENOMEM;
    }

    if (!ksu_stub_page) {
        ksu_stub_page = ksu_exec_alloc(PAGE_SIZE);
        if (!ksu_stub_page) {
            mutex_unlock(&ksu_site_lock);
            return -ENOMEM;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
        set_memory_rox((unsigned long)ksu_stub_page, 1);
#else
        set_memory_ro((unsigned long)ksu_stub_page, 1);
        set_memory_x((unsigned long)ksu_stub_page, 1);
#endif
    }

    if (ksu_stub_next >= (int)(PAGE_SIZE / KSU_STUB_SIZE)) {
        mutex_unlock(&ksu_site_lock);
        pr_err("ksu: stub page full\n");
        return -ENOMEM;
    }

    displaced_insn = *(u32 *)current_fn;

    /* Advance past any BTI/PAC preamble instructions (up to 2) so we patch
     * real code and don't clobber the BTI landing pad.  Indirect calls from
     * the syscall table use BLR and trigger an EL1 BTI violation if fn+0 is
     * no longer a valid landing pad. */
    int preamble_skip = 0;
    while (preamble_skip < 2 && ksu_insn_is_bti_landing_pad(displaced_insn)) {
        preamble_skip++;
        displaced_insn = *(u32 *)((u8 *)current_fn + preamble_skip * 4);
    }
    void *patch_addr = (u8 *)current_fn + preamble_skip * 4;
    void *stub_resume = (u8 *)current_fn + (preamble_skip + 1) * 4;

    if (ksu_insn_is_pc_relative(displaced_insn)) {
        mutex_unlock(&ksu_site_lock);
        pr_err("ksu: %pS: insn at +%d is PC-relative, cannot install\n", current_fn, preamble_skip * 4);
        return -EINVAL;
    }

    branch_b = ksu_encode_b(patch_addr, new_fn);
    if (!branch_b) {
        mutex_unlock(&ksu_site_lock);
        pr_err("ksu: %p → %p branch out of ±128MB range\n", patch_addr, new_fn);
        return -ERANGE;
    }

    stub_idx = ksu_stub_next++;
    stub = ksu_stub_page + stub_idx * KSU_STUB_SIZE;

    stub_insns[0] = displaced_insn;
    stub_insns[1] = ksu_encode_b(stub + 8, stub_resume);
    if (!stub_insns[1]) {
        ksu_stub_next--;
        mutex_unlock(&ksu_site_lock);
        pr_err("ksu: stub → fn resume branch out of range\n");
        return -ERANGE;
    }

    /* Stub page is RO+X; write each word via fixmap (same path as kprobes).
     * KCFI hash is copied from current_fn-4 so indirect callers pass the check. */
    aarch64_insn_write((u8 *)stub + 0, *(u32 *)((u8 *)current_fn - 4)); /* KCFI hash */
    aarch64_insn_write((u8 *)stub + 4, stub_insns[0]); /* displaced insn */
    aarch64_insn_write((u8 *)stub + 8, stub_insns[1]); /* B fn resume */

    ret = aarch64_insn_patch_text(&patch_addr, &branch_b, 1);
    if (ret) {
        ksu_stub_next--;
        mutex_unlock(&ksu_site_lock);
        return ret;
    }

    ksu_sites[ksu_site_count++] = (struct ksu_branch_site){
        .fn_addr = current_fn,
        .displaced_insn = displaced_insn,
        .stub_idx = stub_idx,
        .preamble_skip = preamble_skip,
    };
    pr_info("ksu: branch site installed: %pS → %pS (stub[%d])\n", current_fn, new_fn, stub_idx);

    mutex_unlock(&ksu_site_lock);
    return 0;
}

void ksu_rkp_branch_exit(void)
{
    if (ksu_stub_page) {
        set_memory_nx((unsigned long)ksu_stub_page, 1);
        ksu_exec_free(ksu_stub_page);
        ksu_stub_page = NULL;
        ksu_stub_next = 0;
    }
}

void *ksu_rkp_get_stub(void *fn)
{
    struct ksu_branch_site *site;
    void *result = NULL;

    mutex_lock(&ksu_site_lock);
    site = ksu_find_site(fn);
    if (site && ksu_stub_page)
        result = ksu_stub_page + site->stub_idx * KSU_STUB_SIZE + 4;
    mutex_unlock(&ksu_site_lock);
    return result;
}

void rkp_jb_exit(void)
{
    ksu_rkp_branch_exit();
    static_branch_disable(&ksu_rkp_key);
}

#else /* !__aarch64__ */

void rkp_jb_exit(void)
{
    static_branch_disable(&ksu_rkp_key);
}

int ksu_rkp_branch_patch(void *dst, void *src)
{
    return -ENOSYS;
}
void *ksu_rkp_get_stub(void *fn)
{
    return NULL;
}

#endif /* __aarch64__ */
