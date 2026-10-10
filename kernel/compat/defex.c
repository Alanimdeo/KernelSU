#include "hook/patch_memory.h"
#include "infra/symbol_resolver.h"
#include "klog.h"

static void *defex_enforce_fn;
static int defex_allow(void)
{
    return 0;
}

void defex_jb_init(void)
{
    void *new_fn = defex_allow;

    defex_enforce_fn = (void *)ksu_resolve_symbol_for_functable_hook("task_defex_enforce");
    if (!defex_enforce_fn)
        return;

    if (ksu_patch_text(&defex_enforce_fn, &new_fn, sizeof(void *), 0)) {
        pr_warn("KSU: DEFEX patch failed\n");
        return;
    }
    pr_info("KSU: Samsung DEFEX detected\n");
}
