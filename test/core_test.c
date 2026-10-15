// Host-side checks for openpak-fetchd's core (make test). Optional arguments:
//   core_test <ceiling.json> <profile.json>   also verify a live envelope under the REAL pinned key
//                                             and build its block
#include "../source/core.h"
#include "fixtures.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int passed, failed;
#define CHECK(c) do { if (c) passed++; else { failed++; printf("FAIL line %d: %s\n", __LINE__, #c); } } while (0)

static char *dupstr(const char *s) { char *d = malloc(strlen(s) + 16); strcpy(d, s); return d; }
static char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *b = malloc(1 << 20);
    *len = fread(b, 1, (1 << 20) - 1, f);
    b[*len] = 0;
    fclose(f);
    return b;
}

static fd_pinned_key test_key;
static const fd_pinned_key *real_keys;
static int real_count;
static void use_real_keys(void) { fd_keys = real_keys; fd_key_count = real_count; }

static void use_test_key(void) {
    test_key.keyid = test_keyid;
    memcpy(test_key.pub, test_pub, 32);
    fd_keys = &test_key;
    fd_key_count = 1;
}

static void test_envelope(void) {
    use_test_key();
    char err[200];
    fd_ceiling c;
    char *e = dupstr(ENV_V3);
    CHECK(fd_ceiling_verify(e, strlen(ENV_V3), &c, err, sizeof(err)));
    CHECK(c.version == 3 && c.count == 3 && strcmp(c.families[2], ".demonware.net") == 0);
    CHECK(fd_ceiling_covers(&c, "x.demonware.net") && fd_ceiling_covers(&c, "demonware.net") && !fd_ceiling_covers(&c, "evil.example.com"));
    free(e);

    // tampered payload (one family changed after signing) and the other bad envelopes
    e = dupstr(ENV_V3_TAMPERED); CHECK(!fd_ceiling_verify(e, strlen(e), &c, err, sizeof(err))); free(e);
    e = dupstr(ENV_V3_OTHER_KEY); CHECK(!fd_ceiling_verify(e, strlen(e), &c, err, sizeof(err))); free(e);
    e = dupstr(ENV_V3_WRONG_KEYID); CHECK(!fd_ceiling_verify(e, strlen(e), &c, err, sizeof(err))); free(e);
    e = dupstr(ENV_V4_BAD_FAMILY); CHECK(!fd_ceiling_verify(e, strlen(e), &c, err, sizeof(err))); free(e);
    // one flipped base64 character of an otherwise untouched, validly signed envelope
    e = dupstr(ENV_V3);
    char *p = strstr(e, "eyJ0eXBl");
    p[40] = p[40] == 'A' ? 'B' : 'A';
    CHECK(!fd_ceiling_verify(e, strlen(e), &c, err, sizeof(err)));
    free(e);
    // the real pinned key must not accept the test key's envelope
    use_real_keys();
    e = dupstr(ENV_V3);
    CHECK(!fd_ceiling_verify(e, strlen(e), &c, err, sizeof(err)));
    free(e);
    use_test_key();
    // garbage
    e = dupstr("{\"payload\":"); CHECK(!fd_ceiling_verify(e, strlen(e), &c, err, sizeof(err))); free(e);
    e = dupstr("not json"); CHECK(!fd_ceiling_verify(e, strlen(e), &c, err, sizeof(err)));
    CHECK(!fd_ceiling_verify(e, 0, &c, err, sizeof(err)));
    free(e);
}

static void test_version_rule(void) {
    use_test_key();
    char err[200];
    fd_ceiling c;
    char *e = dupstr(ENV_V2);
    CHECK(fd_ceiling_check(e, strlen(e), 0, &c, err, sizeof(err)) && c.version == 2);
    free(e); e = dupstr(ENV_V2);
    CHECK(!fd_ceiling_check(e, strlen(e), 3, &c, err, sizeof(err)));      // regression: 2 < 3
    CHECK(c.version == 0 && c.count == 0);                                // nothing leaks out
    free(e); e = dupstr(ENV_V3);
    CHECK(fd_ceiling_check(e, strlen(e), 3, &c, err, sizeof(err)));       // equal is fine
    free(e); e = dupstr(ENV_V3);
    CHECK(!fd_ceiling_check(e, strlen(e), 4, &c, err, sizeof(err)));
    free(e);
}

static const char *SAMPLE_HOSTS =
    "# my own hosts\n"
    "127.0.0.1 example.test\n"
    "#openpak-off# 10.9.9.9 *.nintendo.net\n"
    "\n"
    "# >>> openpak >>>\n"
    "1.1.1.1 old.example.com\n"
    "1.1.1.1 *.nintendo.net\n"
    "# <<< openpak <<<\n"
    "192.0.2.5 after.example.test\n"
    "# tail without newline";

static void test_block(void) {
    use_test_key();
    char err[200], block[0x6000];
    fd_ceiling c;
    char *e = dupstr(ENV_V3);
    CHECK(fd_ceiling_verify(e, strlen(e), &c, err, sizeof(err)));
    free(e);
    // the NRO test PROFILE: .nintendo.net not in this ceiling's... it is; .newfamily.org/.com/evil are not
    char *prof = dupstr(PROFILE);
    size_t bl = 0;
    fd_stats st;
    CHECK(fd_build_block(prof, strlen(PROFILE), &c, NULL, block, sizeof(block), &bl, &st, err, sizeof(err)));
    CHECK(strncmp(block, FD_BEGIN "\n", strlen(FD_BEGIN) + 1) == 0);
    CHECK(strcmp(block + bl - strlen(FD_END) - 1, FD_END "\n") == 0);
    CHECK(strcmp(st.server, "198.51.100.7") == 0);
    CHECK(strstr(block, "198.51.100.7 *.s.n.srv.nintendo.net\n") != NULL);   // the nintendo.net split
    CHECK(strstr(block, " *.nintendo.net\n") == NULL);                        // replaced by its services
    CHECK(strstr(block, "198.51.100.7 nintendo.net\n") != NULL);              // apex
    CHECK(strstr(block, "nncs2-lp1") == NULL);                                // NAT check never redirected
    CHECK(strstr(block, "newfamily") == NULL && strstr(block, "evil.example") == NULL);
    CHECK(strstr(st.dropped, ".newfamily.org") && strstr(st.dropped, "bad name.nintendo.net"));
    CHECK(strstr(block, "x.com") == NULL);                                    // injected line dropped
    free(prof);

    // server.txt wins over the profile address
    prof = dupstr(PROFILE);
    CHECK(fd_build_block(prof, strlen(PROFILE), &c, "10.1.2.3", block, sizeof(block), &bl, &st, err, sizeof(err)));
    CHECK(strstr(block, "10.1.2.3 x.demonware.net\n") && !strstr(block, "198.51.100.7"));
    free(prof);

    // refusals: empty rule set, wrong platform, wrong schema, not json
    prof = dupstr("{\"version\":1,\"platform\":\"switch\",\"redirect\":{\"suffixes\":[\".nope.org\"],\"exact\":[]}}");
    CHECK(!fd_build_block(prof, strlen(prof), &c, NULL, block, sizeof(block), &bl, &st, err, sizeof(err)));
    free(prof);
    prof = dupstr("{\"version\":1,\"platform\":\"wiiu\",\"redirect\":{\"suffixes\":[\".nintendo.net\"]}}");
    CHECK(!fd_build_block(prof, strlen(prof), &c, NULL, block, sizeof(block), &bl, &st, err, sizeof(err)));
    free(prof);
    prof = dupstr("{\"version\":2,\"platform\":\"switch\",\"redirect\":{\"suffixes\":[\".nintendo.net\"]}}");
    CHECK(!fd_build_block(prof, strlen(prof), &c, NULL, block, sizeof(block), &bl, &st, err, sizeof(err)));
    free(prof);
    prof = dupstr("{\"version\":1,\"platform\":\"switch\",\"redirect\":");
    CHECK(!fd_build_block(prof, strlen(prof), &c, NULL, block, sizeof(block), &bl, &st, err, sizeof(err)));
    free(prof);

    // overrides come after the wildcards
    prof = dupstr("{\"version\":1,\"platform\":\"switch\",\"redirect\":{\"suffixes\":[\".demonware.net\"],"
                  "\"overrides\":{\"a.demonware.net\":\"9.9.9.9\"}}}");
    CHECK(fd_build_block(prof, strlen(prof), &c, NULL, block, sizeof(block), &bl, &st, err, sizeof(err)));
    CHECK(strstr(block, "9.9.9.9 a.demonware.net\n") > strstr(block, "*.demonware.net\n"));
    free(prof);

    // too small a buffer is an error, not a truncated block
    prof = dupstr(PROFILE);
    CHECK(!fd_build_block(prof, strlen(PROFILE), &c, NULL, block, 200, &bl, &st, err, sizeof(err)));
    free(prof);
}

static void test_replace(void) {
    static char out[0x8000], out2[0x8000];
    char err[200];
    size_t ol = 0, o2 = 0;
    const char *block = FD_BEGIN "\n9.9.9.9 new.example.com\n9.9.9.9 *.nintendo.com\n" FD_END "\n";
    size_t bl = strlen(block);
    const char *in = SAMPLE_HOSTS;

    CHECK(fd_apply_block(in, strlen(in), block, bl, out, sizeof(out), &ol, err, sizeof(err)) == FD_APPLY_OK);
    // every foreign line survives, in place and byte for byte
    CHECK(strncmp(out, "# my own hosts\n127.0.0.1 example.test\n#openpak-off# 10.9.9.9 *.nintendo.net\n\n", 77) == 0);
    CHECK(strstr(out, "192.0.2.5 after.example.test\n# tail without newline") != NULL);
    CHECK(strstr(out, "old.example.com") == NULL && strstr(out, "9.9.9.9 new.example.com\n") != NULL);
    const char *tailpos = strstr(out, "192.0.2.5");
    CHECK(tailpos && strcmp(tailpos, "192.0.2.5 after.example.test\n# tail without newline") == 0);
    // idempotent: applying the same block again changes nothing
    CHECK(fd_apply_block(out, ol, block, bl, out2, sizeof(out2), &o2, err, sizeof(err)) == FD_APPLY_OK);
    CHECK(o2 == ol && memcmp(out, out2, ol) == 0);
    // diff summary
    int rem, add, kept; size_t oldb;
    fd_block_diff(in, strlen(in), block, bl, &rem, &add, &kept, &oldb);
    CHECK(rem == 2 && add == 2 && kept == 2 && oldb == strlen("# >>> openpak >>>\n1.1.1.1 old.example.com\n1.1.1.1 *.nintendo.net\n# <<< openpak <<<\n"));
    fd_block_diff(out, ol, block, bl, &rem, &add, &kept, &oldb);
    CHECK(rem == 0 && add == 0 && kept == 4);

    // a file with the block at the very end without a trailing newline
    const char *in2 = "127.0.0.1 a.test\n" FD_BEGIN "\n1.1.1.1 x\n" FD_END;
    CHECK(fd_apply_block(in2, strlen(in2), block, bl, out, sizeof(out), &ol, err, sizeof(err)) == FD_APPLY_OK);
    CHECK(strncmp(out, "127.0.0.1 a.test\n", 17) == 0 && strcmp(out + 17, block) == 0);

    // no block: left alone (the console never chose OpenPak); empty and missing-end/duplicate: refused
    CHECK(fd_apply_block("127.0.0.1 a\n", 12, block, bl, out, sizeof(out), &ol, err, sizeof(err)) == FD_APPLY_NO_BLOCK && ol == 0);
    CHECK(fd_apply_block("", 0, block, bl, out, sizeof(out), &ol, err, sizeof(err)) == FD_APPLY_NO_BLOCK);
    const char *noend = "x\n" FD_BEGIN "\n1.1.1.1 x\n";
    CHECK(fd_apply_block(noend, strlen(noend), block, bl, out, sizeof(out), &ol, err, sizeof(err)) == FD_APPLY_ERROR);
    const char *dup = FD_BEGIN "\na\n" FD_END "\n" FD_BEGIN "\nb\n" FD_END "\n";
    CHECK(fd_apply_block(dup, strlen(dup), block, bl, out, sizeof(out), &ol, err, sizeof(err)) == FD_APPLY_ERROR);
    const char *twobegin = FD_BEGIN "\n" FD_BEGIN "\n" FD_END "\n";
    CHECK(fd_apply_block(twobegin, strlen(twobegin), block, bl, out, sizeof(out), &ol, err, sizeof(err)) == FD_APPLY_ERROR);
}

static void test_oversize(void) {
    static char big[0x9000], out[0x9000];
    char err[200];
    size_t ol = 0;
    const char *block = FD_BEGIN "\n9.9.9.9 new.example.com\n" FD_END "\n";
    size_t bl = strlen(block);
    // foreign lines make the result land just under the safe limit: accepted
    size_t n = 0;
    while (n < FD_HOSTS_SAFE - 200) n += (size_t)sprintf(big + n, "127.0.0.1 filler%05zu.example.test\n", n);
    n += (size_t)sprintf(big + n, "%s\n1.1.1.1 old\n%s\n", FD_BEGIN, FD_END);
    CHECK(n < FD_HOSTS_SAFE);
    CHECK(fd_apply_block(big, n, block, bl, out, sizeof(out), &ol, err, sizeof(err)) == FD_APPLY_OK && ol < FD_HOSTS_SAFE);
    // one more filler line pushes it to the limit: refused, nothing produced
    n = 0;
    while (n < FD_HOSTS_SAFE) n += (size_t)sprintf(big + n, "127.0.0.1 filler%05zu.example.test\n", n);
    n += (size_t)sprintf(big + n, "%s\n1.1.1.1 old\n%s\n", FD_BEGIN, FD_END);
    CHECK(fd_apply_block(big, n, block, bl, out, sizeof(out), &ol, err, sizeof(err)) == FD_APPLY_ERROR && ol == 0);
    // at and beyond 0x8000
    n = 0;
    while (n < FD_HOSTS_MAX + 100) n += (size_t)sprintf(big + n, "127.0.0.1 filler%05zu.example.test\n", n);
    n += (size_t)sprintf(big + n, "%s\n1.1.1.1 old\n%s\n", FD_BEGIN, FD_END);
    CHECK(fd_apply_block(big, n, block, bl, out, 0x8100, &ol, err, sizeof(err)) == FD_APPLY_ERROR);
    printf("  (oversize error text: %s)\n", err);
}


static int g_commits;
static void commit_count(void) { g_commits++; }
static void quiet(const char *fmt, ...) { (void)fmt; }

static void wr(const char *path, const char *data) { FILE *f = fopen(path, "wb"); fputs(data, f); fclose(f); }
static char *rd(const char *path) { size_t n; return slurp(path, &n); }

static void test_update_hosts(void) {
    char dir[512], d[600], e[600], dp[640], ep[640];
    const char *tmp = getenv("TMPDIR");
    snprintf(dir, sizeof(dir), "%s/fd_core_test_XXXXXX", tmp ? tmp : ".");
    if (!mkdtemp(dir)) { perror("mkdtemp"); failed++; return; }
    snprintf(d, sizeof(d), "%s/default.txt", dir);
    snprintf(e, sizeof(e), "%s/emummc.txt", dir);
    snprintf(dp, sizeof(dp), "%s.openpak-prev", d);
    snprintf(ep, sizeof(ep), "%s.openpak-prev", e);
    const char *paths[2] = {d, e};
    const char *block = FD_BEGIN "\n9.9.9.9 new.example.com\n" FD_END "\n";
    size_t bl = strlen(block);
    bool changed;
    char *got;

    // dry: nothing may change, the summary is only logged
    wr(d, SAMPLE_HOSTS);
    CHECK(fd_update_hosts(paths, 2, block, bl, NULL, false, &changed, quiet, commit_count) == 0 && !changed);
    got = rd(d); CHECK(strcmp(got, SAMPLE_HOSTS) == 0); free(got);
    CHECK(access(dp, F_OK) != 0 && access(ep, F_OK) != 0);

    // real, emummc.txt absent: default.txt rewritten, previous kept, foreign lines intact
    CHECK(fd_update_hosts(paths, 2, block, bl, NULL, true, &changed, quiet, commit_count) == 1 && changed);
    got = rd(d);
    CHECK(strstr(got, "9.9.9.9 new.example.com\n") && !strstr(got, "old.example.com"));
    CHECK(strstr(got, "127.0.0.1 example.test\n#openpak-off# 10.9.9.9 *.nintendo.net\n") && strstr(got, "192.0.2.5 after.example.test\n# tail without newline"));
    free(got);
    got = rd(dp); CHECK(strcmp(got, SAMPLE_HOSTS) == 0); free(got);
    CHECK(access(ep, F_OK) != 0);
    char tmpf[700]; snprintf(tmpf, sizeof(tmpf), "%s.openpak-tmp", d);
    CHECK(access(tmpf, F_OK) != 0);                                       // no temp file left

    // idempotent: the same block again writes nothing and keeps the first .openpak-prev
    CHECK(fd_update_hosts(paths, 2, block, bl, NULL, true, &changed, quiet, commit_count) == 0 && !changed);
    got = rd(dp); CHECK(strcmp(got, SAMPLE_HOSTS) == 0); free(got);

    // both files: each gets the block, a file without a block is skipped untouched
    wr(e, "127.0.0.1 only.foreign\n");
    CHECK(fd_update_hosts(paths, 2, FD_BEGIN "\n8.8.8.8 other.example.com\n" FD_END "\n", strlen(FD_BEGIN "\n8.8.8.8 other.example.com\n" FD_END "\n"), NULL, true, &changed, quiet, commit_count) == 1);
    got = rd(e); CHECK(strcmp(got, "127.0.0.1 only.foreign\n") == 0); free(got);
    CHECK(access(ep, F_OK) != 0);

    // refusal in one file leaves BOTH alone: emummc.txt has a damaged block
    wr(d, SAMPLE_HOSTS);
    wr(e, "x\n" FD_BEGIN "\n1.1.1.1 broken\n");
    CHECK(fd_update_hosts(paths, 2, block, bl, NULL, true, &changed, quiet, commit_count) == -1 && !changed);
    got = rd(d); CHECK(strcmp(got, SAMPLE_HOSTS) == 0); free(got);
    got = rd(e); CHECK(strcmp(got, "x\n" FD_BEGIN "\n1.1.1.1 broken\n") == 0); free(got);

    // oversize in one file: same
    static char big[0x9000];
    size_t n = 0;
    while (n < FD_HOSTS_SAFE + 100) n += (size_t)sprintf(big + n, "127.0.0.1 filler%05zu.example.test\n", n);
    sprintf(big + n, "%s\n1.1.1.1 old\n%s\n", FD_BEGIN, FD_END);
    wr(e, big);
    CHECK(fd_update_hosts(paths, 2, block, bl, NULL, true, &changed, quiet, commit_count) == -1 && !changed);
    got = rd(d); CHECK(strcmp(got, SAMPLE_HOSTS) == 0); free(got);
    CHECK(access(dp, F_OK) == 0);   // the earlier, unrelated prev is still there; d itself unchanged
    CHECK(g_commits > 0);

    char cmd[700];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) failed++;
}

// Conflict neutralisation (hosts.c line_targets_ours): foreign lines for managed names are commented out.
static void test_conflicts(void) {
    static char out[0x8000], out2[0x8000];
    char err[200];
    size_t ol = 0, o2 = 0;
    int neut = 0;
    const char *block = FD_BEGIN "\n9.9.9.9 *.demonware.net\n9.9.9.9 demonware.net\n9.9.9.9 exact.example.com\n" FD_END "\n";
    size_t bl = strlen(block);
    const char *in =
        "# keep\n"
        "1.1.1.1 a.demonware.net\n"            // wildcard suffix: neutralised, before the block
        "1.1.1.1 demonware.net\n"              // apex
        "1.1.1.1 exact.example.com extra\n"    // exact name, more tokens after
        "1.1.1.1 Exact.Example.com\n"          // case differs: untouched (matching is case-sensitive)
        "1.1.1.1 A.DEMONWARE.NET\n"            // case differs: untouched
        "  2.2.2.2\tb.demonware.net\r\n"       // leading blanks, tab, CRLF
        "1.1.1.1 exact.example.com.evil\n"     // longer name: untouched
        "1.1.1.1 notdemonware.net\n"           // not a subdomain of the family: untouched
        "1.1.1.1 other.example.org\n"          // unrelated
        "#1.1.1.1 c.demonware.net\n"           // comment
        "#openpak-off# 1.1.1.1 d.demonware.net\n"   // already prefixed
        "\n"
        "1.1.1.1 demonware.net extra.example.org\n"   // only the first hostname counts
        "# >>> openpak >>>\n1.1.1.1 old.example.com\n# <<< openpak <<<\n"
        "3.3.3.3 after.demonware.net\n"        // after the block: neutralised too
        "4.4.4.4 last.demonware.net";           // last line, no newline
    CHECK(fd_apply_block_ex(in, strlen(in), block, bl, NULL, out, sizeof(out), &ol, &neut, err, sizeof(err)) == FD_APPLY_OK);
    CHECK(neut == 7);
    CHECK(strstr(out, "# keep\n#openpak-off# 1.1.1.1 a.demonware.net\n#openpak-off# 1.1.1.1 demonware.net\n#openpak-off# 1.1.1.1 exact.example.com extra\n"));
    CHECK(strstr(out, "\n1.1.1.1 Exact.Example.com\n1.1.1.1 A.DEMONWARE.NET\n#openpak-off# "));
    CHECK(strstr(out, "#openpak-off#   2.2.2.2\tb.demonware.net\r\n"));
    CHECK(strstr(out, "\n1.1.1.1 exact.example.com.evil\n1.1.1.1 notdemonware.net\n1.1.1.1 other.example.org\n#1.1.1.1 c.demonware.net\n"));
    CHECK(strstr(out, "\n#openpak-off# 1.1.1.1 d.demonware.net\n\n") && !strstr(out, "#openpak-off# #openpak-off#"));
    CHECK(strstr(out, "#openpak-off# 1.1.1.1 demonware.net extra.example.org\n"));
    CHECK(strstr(out, "#openpak-off# 3.3.3.3 after.demonware.net\n#openpak-off# 4.4.4.4 last.demonware.net") );
    CHECK(strlen(out) == ol && strstr(out, "old.example.com") == NULL && strstr(out, "9.9.9.9 exact.example.com\n"));
    CHECK(out[ol - 1] == 't');                                              // no newline invented
    // the block's own lines are never prefixed
    CHECK(strstr(out, FD_BEGIN "\n9.9.9.9 *.demonware.net\n"));
    // idempotent
    int n2 = -1;
    CHECK(fd_apply_block_ex(out, ol, block, bl, NULL, out2, sizeof(out2), &o2, &n2, err, sizeof(err)) == FD_APPLY_OK);
    CHECK(n2 == 0 && o2 == ol && memcmp(out, out2, ol) == 0);
    // explicit patterns (policy hostnames, wider than the block's lines) are honoured
    const char *pin = "1.1.1.1 q.nintendo.net\n1.1.1.1 nintendo.net\n# >>> openpak >>>\n# <<< openpak <<<\n";
    CHECK(fd_apply_block_ex(pin, strlen(pin), block, bl, "*.nintendo.net\nnintendo.net\n", out, sizeof(out), &ol, &neut, err, sizeof(err)) == FD_APPLY_OK && neut == 2);
    CHECK(fd_apply_block_ex(pin, strlen(pin), block, bl, NULL, out, sizeof(out), &ol, &neut, err, sizeof(err)) == FD_APPLY_OK && neut == 0);
    // no block: nothing at all is touched
    CHECK(fd_apply_block_ex("1.1.1.1 a.demonware.net\n", 25, block, bl, NULL, out, sizeof(out), &ol, &neut, err, sizeof(err)) == FD_APPLY_NO_BLOCK && neut == 0);

    // size guard counts the prefixes: a file just under the limit without them is refused with them
    static char big[0x9000];
    size_t n = 0;
    int k = 0;
    while (n + 40 < FD_HOSTS_SAFE - 300) n += (size_t)sprintf(big + n, "1.1.1.1 f%05d.demonware.net\n", k++);
    n += (size_t)sprintf(big + n, "%s\n1.1.1.1 old\n%s\n", FD_BEGIN, FD_END);
    CHECK(n < FD_HOSTS_SAFE - bl);
    CHECK(fd_apply_block_ex(big, n, block, bl, NULL, out, sizeof(out), &ol, &neut, err, sizeof(err)) == FD_APPLY_ERROR && ol == 0 && neut == 0);
    CHECK(fd_apply_block_ex(big, n, block, bl, "unrelated.example\n", out, sizeof(out), &ol, &neut, err, sizeof(err)) == FD_APPLY_OK && neut == 0);

    // fd_update_hosts: dry reports without writing, real writes, repeat is a no-op, .openpak-prev kept
    char dir[512], d[600], e[600], dp[640];
    const char *tmp = getenv("TMPDIR");
    snprintf(dir, sizeof(dir), "%s/fd_core_test_XXXXXX", tmp ? tmp : ".");
    if (!mkdtemp(dir)) { perror("mkdtemp"); failed++; return; }
    snprintf(d, sizeof(d), "%s/default.txt", dir);
    snprintf(e, sizeof(e), "%s/emummc.txt", dir);
    snprintf(dp, sizeof(dp), "%s.openpak-prev", d);
    const char *paths[2] = {d, e};
    bool changed;
    char *got;
    wr(d, in);
    wr(e, "1.1.1.1 z.demonware.net\n" FD_BEGIN "\n1.1.1.1 old\n" FD_END "\n");
    CHECK(fd_update_hosts(paths, 2, block, bl, NULL, false, &changed, quiet, commit_count) == 0 && !changed);
    got = rd(d); CHECK(strcmp(got, in) == 0); free(got);
    CHECK(access(dp, F_OK) != 0);
    CHECK(fd_update_hosts(paths, 2, block, bl, NULL, true, &changed, quiet, commit_count) == 2 && changed);
    got = rd(d); CHECK(strstr(got, "#openpak-off# 1.1.1.1 a.demonware.net\n") && strcmp(got, out2) == 0); free(got);
    got = rd(e); CHECK(strncmp(got, "#openpak-off# 1.1.1.1 z.demonware.net\n", 38) == 0); free(got);
    got = rd(dp); CHECK(strcmp(got, in) == 0); free(got);
    CHECK(fd_update_hosts(paths, 2, block, bl, NULL, true, &changed, quiet, commit_count) == 0 && !changed);
    // a refusal (size) with conflicting lines leaves every file alone
    wr(e, big);
    CHECK(fd_update_hosts(paths, 2, block, bl, NULL, true, &changed, quiet, commit_count) == -1 && !changed);
    got = rd(d); CHECK(strcmp(got, out2) == 0); free(got);
    char cmd[700];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) failed++;
}

static void test_http(void) {
    char err[100];
    int status; char *body; size_t bl;
    char a[512];
    strcpy(a, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\nhello");
    CHECK(fd_http_body(a, strlen(a), &status, &body, &bl, err, sizeof(err)) && status == 200 && bl == 5 && memcmp(body, "hello", 5) == 0);
    strcpy(a, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
    CHECK(fd_http_body(a, strlen(a), &status, &body, &bl, err, sizeof(err)) && bl == 11 && memcmp(body, "hello world", 11) == 0);
    strcpy(a, "HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort");
    CHECK(!fd_http_body(a, strlen(a), &status, &body, &bl, err, sizeof(err)));
    strcpy(a, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel");
    CHECK(!fd_http_body(a, strlen(a), &status, &body, &bl, err, sizeof(err)));
    strcpy(a, "HTTP/1.1 301 Moved\r\nLocation: https://x\r\n\r\n");
    CHECK(fd_http_body(a, strlen(a), &status, &body, &bl, err, sizeof(err)) && status == 301);
    strcpy(a, "garbage");
    CHECK(!fd_http_body(a, strlen(a), &status, &body, &bl, err, sizeof(err)));
}

static void test_json_escapes(void) {
    // escapes in a string value reach the block exactly like json-c would deliver them
    use_test_key();
    char err[200], block[0x6000];
    fd_ceiling c;
    char *e = dupstr(ENV_V3);
    CHECK(fd_ceiling_verify(e, strlen(e), &c, err, sizeof(err)));
    free(e);
    char *prof = dupstr("{\"version\":1,\"platform\":\"switch\",\"redirect\":{\"suffixes\":[\".demon\\u0077are.net\"],\"exact\":[\"a\\/b.demonware.net\"]}}");
    size_t bl;
    fd_stats st;
    CHECK(fd_build_block(prof, strlen(prof), &c, NULL, block, sizeof(block), &bl, &st, err, sizeof(err)));
    CHECK(strstr(block, "*.demonware.net\n") != NULL);
    CHECK(strstr(st.dropped, "a/b.demonware.net") != NULL);      // '/' is not a hostname character
    free(prof);
}

// Live data under the REAL pinned key: argv[1] envelope, argv[2] profile, optional argv[3]
// receives the generated block (for the comparison against the NRO's own code).
static void test_live(const char *cpath, const char *ppath, const char *blockpath) {
    use_real_keys();
    size_t cl = 0, pl = 0;
    char *prof = slurp(ppath, &pl);
    char err[200], block[0x6000];
    fd_ceiling c;
    char *env = slurp(cpath, &cl);
    CHECK(env && prof);
    if (!env || !prof) return;
    CHECK(fd_ceiling_check(env, cl, 0, &c, err, sizeof(err)));
    printf("  live ceiling: version %lld, %d switch families\n", c.version, c.count);
    free(env);
    // the same bytes must be refused once a higher version has been seen
    env = slurp(cpath, &cl);
    fd_ceiling c2;
    CHECK(!fd_ceiling_check(env, cl, c.version + 1, &c2, err, sizeof(err)));
    free(env);
    // one flipped payload character of the live envelope
    env = slurp(cpath, &cl);
    char *p = strstr(env, "\"payload\"");
    p[20] = p[20] == 'A' ? 'B' : 'A';
    CHECK(!fd_ceiling_verify(env, cl, &c2, err, sizeof(err)));
    free(env);
    size_t bl = 0;
    fd_stats st;
    CHECK(fd_build_block(prof, pl, &c, NULL, block, sizeof(block), &bl, &st, err, sizeof(err)));
    printf("  live block: %zu bytes, %d host lines from %d rules, server %s, dropped: [%s]\n", bl, st.lines, st.rules, st.server, st.dropped);
    CHECK(bl < FD_HOSTS_SAFE);
    free(prof);
    if (blockpath) {
        FILE *f = fopen(blockpath, "wb");
        CHECK(f != NULL);
        if (f) { fwrite(block, 1, bl, f); fclose(f); }
    }
}

int main(int argc, char **argv) {
    real_keys = fd_keys;
    real_count = fd_key_count;
    if (argc >= 3) test_live(argv[1], argv[2], argc >= 4 ? argv[3] : NULL);
    test_envelope();
    test_version_rule();
    test_block();
    test_replace();
    test_oversize();
    test_update_hosts();
    test_conflicts();
    test_http();
    test_json_escapes();
    printf("core_test: %d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
