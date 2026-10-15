/*
 * openpak-fetchd: boot2 sysmodule, title 0x01FE000000000F00. Keeps the OpenPak block of the
 * Atmosphere hosts files in step with openpak.org.
 *
 * Every cycle: nifm connected -> resolve openpak.org (sfdnsres, original session) ->
 * bsdInitialize -> https (ssl service, system trust store) GET the signed ceiling and the
 * switch profile -> verify Ed25519 against the pinned key, rollback rule -> build the block
 * exactly as console/openpak-nro would -> rewrite ONLY the marked block of
 * /atmosphere/hosts/default.txt and emummc.txt (or, in dry mode, write the would-be block
 * to /atmosphere/openpak-fetchd/dry-block.txt) -> tell dns_mitm to reload (command 65000).
 * One cycle after the network is up, then one every 6 hours of uptime.
 *
 * Gate files (all under sdmc:/atmosphere/):
 *   openpak-fetchd.enable   one-shot: run on this boot only (consumed at once). Without it and
 *                           without .auto the process exits silently and writes nothing
 *   openpak-fetchd.auto     persistent: run on every boot (also makes cycles write, see below)
 *   openpak-fetchd.write    real hosts writes are allowed
 *   openpak-fetchd.dry      force dry mode even if .auto/.write exist
 *   Mode: writes happen only if (.auto or .write exists) and .dry does not. Otherwise dry.
 *   openpak-fetchd.stop     checked while idle between cycles: process exits
 *   openpak-fetchd.stage    decimal N: single cycle, stop before step N (1 dns, 2 bsd init,
 *                           3 fetch, 4 verify+build, 5 write/dry output, 6 dns_mitm reload)
 *   openpak-fetchd.delay    seconds to wait after the first "connected" (default 20)
 *   openpak-fetchd.nifmreq  if not connected after 90 s submit one nifm request
 *   openpak-fetchd.reloadtest  call the dns_mitm reload even when nothing was written
 *   openpak-fetchd.running  crash marker written before bsdInitialize of every cycle and removed
 *                           when the cycle ends normally; present at start = exit untouched
 *
 * The log is opened, written, flushed and closed for every line. Every failure is logged and
 * skipped; nothing aborts, nothing secret is logged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <malloc.h>
#include <switch.h>
#include <switch/services/bsd.h>
#include <switch/services/sfdnsres.h>
#include "core.h"

#define ATM "sdmc:/atmosphere/"
#define LOG_PATH      ATM "openpak-fetchd.log"
#define RUNNING_PATH  ATM "openpak-fetchd.running"
#define STATE_DIR     ATM "openpak-fetchd"
#define VERSION_PATH  STATE_DIR "/ceiling.version"
#define DRYBLOCK_PATH STATE_DIR "/dry-block.txt"
#define NRO_VERSION   "sdmc:/switch/openpak/ceiling.version"   /* read only: the NRO's own floor */
#define SERVER_TXT    "sdmc:/switch/openpak/server.txt"        /* read only: the user's address */
#define HOST          "openpak.org"
#define PATH_CEILING  "/api/v1/network/ceiling"
#define PATH_PROFILE  "/api/v1/network/profile?platform=switch"
#define RESP_MAX      0x8000
#define INNER_HEAP_SIZE 0x30000
#define CYCLE_SECONDS (6ULL * 3600ULL)
#define RETRY_SECONDS 300ULL

u32 __nx_applet_type = AppletType_None;
u32 __nx_fs_num_sessions = 1;

void __libnx_initheap(void) {
    static u8 inner_heap[INNER_HEAP_SIZE];
    extern void *fake_heap_start;
    extern void *fake_heap_end;
    fake_heap_start = inner_heap;
    fake_heap_end = inner_heap + sizeof(inner_heap);
}

/* sm stays open for the whole run: sfdnsres (smGetServiceOriginal), bsd and ssl all call into it later. */
void __appInit(void) {
    Result rc = smInitialize();
    if (R_FAILED(rc)) return;
    rc = setsysInitialize();
    if (R_SUCCEEDED(rc)) {
        SetSysFirmwareVersion fw;
        if (R_SUCCEEDED(setsysGetFirmwareVersion(&fw)))
            hosversionSet(MAKEHOSVERSION(fw.major, fw.minor, fw.micro));
        setsysExit();
    }
    if (R_SUCCEEDED(fsInitialize())) fsdevMountSdmc();
}

void __appExit(void) {
    fsdevUnmountAll();
    fsExit();
    smExit();
}

/* libnx bsdInitialize wants tcp tx 0x8000 + rx 0x10000 + udp 0x2400 + 0xA500 = 0x24900, page-rounded
   0x25000 (sb_efficiency 1). A smaller buffer makes it malloc that much from the heap instead
   (tmemCreate): the v2 hardware run died there with Libnx OutOfMemory. 0x28000 keeps it static. */
static u8   g_bsd_tmem[0x28000] __attribute__((aligned(0x1000)));
static u8   g_hostent[0x400];
static char g_req[256];
static char g_resp[RESP_MAX + 1];
static char g_block[0x6000];
static fd_ceiling g_ceil;
static u8 g_addrs[8][4];
static int g_naddr;

static u64 ms_now(void) { return armTicksToNs(armGetSystemTick()) / 1000000ULL; }

static void lg(const char *fmt, ...) {
    char line[400];
    int n = snprintf(line, sizeof(line), "[%7llu ms] ", (unsigned long long)ms_now());
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line + n, sizeof(line) - n - 2, fmt, ap);
    va_end(ap);
    strcat(line, "\n");
    FILE *f = fopen(LOG_PATH, "ab");
    if (!f) return;
    fputs(line, f);
    fflush(f);
    fclose(f);
    fsdevCommitDevice("sdmc");
}

/* "0x559 (Libnx OutOfMemory)": module/desc decoded for the log. */
static const char *rc_text(Result rc, char *buf, size_t cap) {
    static const char *const libnx[] = {"?", "BadReloc", "OutOfMemory", "AlreadyMapped", "BadGetInfo_Stack",
        "BadGetInfo_Heap", "BadQueryMemory", "AlreadyInitialized", "NotInitialized", "NotFound", "IoError",
        "BadInput", "BadReent", "BufferProducerError", "HandleTooEarly", "HeapAllocFailed", "TooManyOverrides"};
    u32 mod = R_MODULE(rc), desc = R_DESCRIPTION(rc);
    if (rc == 0) snprintf(buf, cap, "0x0 (ok)");
    else if (mod == Module_Libnx && desc < sizeof(libnx) / sizeof(*libnx)) snprintf(buf, cap, "0x%x (Libnx %s)", rc, libnx[desc]);
    else if (mod == Module_Kernel) snprintf(buf, cap, "0x%x (Kernel error %u)", rc, desc);
    else snprintf(buf, cap, "0x%x (module %u desc %u)", rc, mod, desc);
    return buf;
}

/* Heap budget line: arena size, malloc'd bytes in use, free bytes, and the unused tail of the fake heap. */
static void heap_report(const char *where) {
    extern void *fake_heap_start;
    extern void *fake_heap_end;
    struct mallinfo mi = mallinfo();
    lg("heap before %s: fake heap total=0x%x, malloc arena=0x%x in use=0x%x free-in-arena=0x%x, never-touched=0x%x",
       where, (unsigned)((char *)fake_heap_end - (char *)fake_heap_start), (unsigned)mi.arena, (unsigned)mi.uordblks,
       (unsigned)mi.fordblks, (unsigned)((char *)fake_heap_end - (char *)fake_heap_start) - (unsigned)mi.arena);
}

static void sleep_s(u64 s) { svcSleepThread(s * 1000000000ULL); }
static int file_exists(const char *p) { struct stat st; return stat(p, &st) == 0; }

static long read_num(const char *p, long def) {
    FILE *f = fopen(p, "rb");
    if (!f) return def;
    char b[32] = {0};
    size_t n = fread(b, 1, sizeof(b) - 1, f);
    fclose(f);
    if (n == 0) return def;
    char *e = NULL;
    long v = strtol(b, &e, 10);
    return (e == b) ? def : v;
}

static u32 be32(const u8 *p) { return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3]; }

/* Serialized hostent ends with u32 count + count*4 address bytes. */
static int tail_addrs(const u8 *buf, u32 size, u8 out[][4], int max) {
    for (u32 c = 1; c <= 8; c++) {
        if (size < 4 * c + 4) break;
        u32 pos = size - 4 * c - 4;
        if (be32(buf + pos) == c) {
            int n = (int)c < max ? (int)c : max;
            for (int i = 0; i < n; i++) memcpy(out[i], buf + pos + 4 + 4 * i, 4);
            return n;
        }
    }
    return 0;
}

/* ---- files ---------------------------------------------------------------------------- */

static int write_plain(const char *path, const void *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t w = fwrite(data, 1, len, f);
    int fl = fflush(f);
    fclose(f);
    fsdevCommitDevice("sdmc");
    return (w == len && fl == 0) ? 0 : -1;
}

static void commit_sd(void) { fsdevCommitDevice("sdmc"); }

/* ---- network -------------------------------------------------------------------------- */

static int connect_ip(const u8 ip[4], u16 port) {
    int fd = bsdSocket(AF_INET, SOCK_STREAM, 0);
    lg("socket fd=%d errno=%d", fd, g_bsdErrno);
    if (fd < 0) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    memcpy(&sa.sin_addr, ip, 4);
    lg("connect %u.%u.%u.%u:%u begin", ip[0], ip[1], ip[2], ip[3], port);
    int r = bsdConnect(fd, (struct sockaddr *)&sa, sizeof(sa));
    lg("connect r=%d errno=%d", r, g_bsdErrno);
    if (r < 0) { bsdClose(fd); return -1; }
    return fd;
}

/* One https GET over a fresh ssl context. On success g_resp holds the response; the body
   (and its length) is located (200 only). */
static bool https_get(const char *path, char **body, size_t *blen) {
    SslContext ctx; SslConnection conn;
    int have_ctx = 0, have_conn = 0, sfd = -1, ssl_fd = -1;
    bool ok = false;
    u32 total = 0;
    Result rc;
    *body = NULL; *blen = 0;

    lg("tls: call sslCreateContext(Auto)");
    rc = sslCreateContext(&ctx, SslVersion_Auto);
    lg("tls: sslCreateContext rc=0x%x", rc);
    if (R_FAILED(rc)) goto done;
    have_ctx = 1;
    lg("tls: call sslContextCreateConnection");
    rc = sslContextCreateConnection(&ctx, &conn);
    lg("tls: sslContextCreateConnection rc=0x%x", rc);
    if (R_FAILED(rc)) goto done;
    have_conn = 1;
    for (int pass = 0; pass < 2 && sfd < 0; pass++)
        for (int i = 0; i < g_naddr && sfd < 0; i++) {
            u8 ip[4];
            for (int k = 0; k < 4; k++) ip[k] = pass == 0 ? g_addrs[i][3 - k] : g_addrs[i][k];
            sfd = connect_ip(ip, 443);
        }
    if (sfd < 0) { lg("tls: FAIL tcp connect :443"); goto done; }
    lg("tls: call sslConnectionSetSocketDescriptor(%d)", sfd);
    rc = sslConnectionSetSocketDescriptor(&conn, sfd, &ssl_fd);
    lg("tls: SetSocketDescriptor rc=0x%x fd=%d", rc, ssl_fd);
    if (R_FAILED(rc)) goto done;
    lg("tls: call sslConnectionSetHostName(%s)", HOST);
    rc = sslConnectionSetHostName(&conn, HOST, (u32)strlen(HOST));
    lg("tls: SetHostName rc=0x%x", rc);
    if (R_FAILED(rc)) goto done;
    rc = sslConnectionSetIoMode(&conn, SslIoMode_Blocking);
    lg("tls: SetIoMode(blocking) rc=0x%x", rc);
    if (R_FAILED(rc)) goto done;
    {
        u32 hs = 0, certs = 0;
        lg("tls: call sslConnectionDoHandshake");
        rc = sslConnectionDoHandshake(&conn, &hs, &certs, NULL, 0);
        lg("tls: DoHandshake rc=0x%x certs=%u", rc, certs);
        if (R_FAILED(rc)) {
            Result vr = sslConnectionGetVerifyCertError(&conn);
            lg("tls: FAIL handshake, verify cert error rc=0x%x", vr);
            goto done;
        }
    }
    {
        int n = snprintf(g_req, sizeof(g_req),
                         "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: openpak-fetchd/2\r\nAccept: application/json\r\n"
                         "Accept-Encoding: identity\r\nConnection: close\r\n\r\n", path, HOST);
        u32 wr = 0;
        lg("tls: call sslConnectionWrite(%d bytes) GET %s", n, path);
        rc = sslConnectionWrite(&conn, g_req, (u32)n, &wr);
        lg("tls: Write rc=0x%x bytes=%u", rc, wr);
        if (R_FAILED(rc)) goto done;
        while (total < RESP_MAX) {
            u32 rd = 0, ev = 0;
            rc = sslConnectionPoll(&conn, SslPollEvent_Read, &ev, 15000);
            if (R_FAILED(rc)) { lg("tls: Poll rc=0x%x, stop reading", rc); break; }
            rc = sslConnectionRead(&conn, g_resp + total, RESP_MAX - total, &rd);
            if (R_FAILED(rc) || rd == 0) { lg("tls: Read rc=0x%x rd=%u, end", rc, rd); break; }
            total += rd;
        }
        g_resp[total] = 0;
    }
    {
        int status = 0;
        char err[128];
        if (total >= RESP_MAX) { lg("tls: response larger than %d bytes, refused", RESP_MAX); goto done; }
        if (!fd_http_body(g_resp, total, &status, body, blen, err, sizeof(err))) { lg("tls: %s", err); goto done; }
        lg("tls: response total=%u status=%d body_bytes=%zu", total, status, *blen);
        ok = status == 200 && *blen > 0;
        if (!ok) *body = NULL;
    }
done:
    if (have_conn) sslConnectionClose(&conn);
    if (ssl_fd >= 0) bsdClose(ssl_fd);
    if (sfd >= 0 && sfd != ssl_fd) bsdClose(sfd);
    if (have_ctx) sslContextClose(&ctx);
    return ok;
}

static bool resolve(void) {
    u32 herr = 0, err = 0, outsz = 0;
    lg("step 1 dns: call sfdnsresGetHostByNameRequest(%s)", HOST);
    memset(g_hostent, 0, sizeof(g_hostent));
    Result rc = sfdnsresGetHostByNameRequest(0, false, HOST, &herr, &err, g_hostent, sizeof(g_hostent), &outsz);
    lg("step 1 dns: rc=0x%x h_errno=%u errno=%u size=%u", rc, herr, err, outsz);
    g_naddr = 0;
    if (R_SUCCEEDED(rc) && outsz && outsz <= sizeof(g_hostent)) g_naddr = tail_addrs(g_hostent, outsz, g_addrs, 4);
    for (int i = 0; i < g_naddr; i++)
        lg("dns addr%d raw=%u.%u.%u.%u (reversed order is the real one on this console)", i,
           g_addrs[i][0], g_addrs[i][1], g_addrs[i][2], g_addrs[i][3]);
    return g_naddr > 0;
}

/* dns_mitm: Atmosphere extension, IResolver command 65000 AtmosphereReloadHostsFile. It only
   exists on the mitm'd session (smGetService, not the original one libnx's sfdnsres uses). */
static void reload_dns_mitm(void) {
    Service srv;
    lg("call smGetService(sfdnsres) for the dns_mitm reload");
    Result rc = smGetService(&srv, "sfdnsres");
    lg("smGetService(sfdnsres) rc=0x%x", rc);
    if (R_FAILED(rc)) return;
    lg("call sfdnsres command 65000 (AtmosphereReloadHostsFile)");
    rc = serviceDispatch(&srv, 65000);
    lg("command 65000 rc=0x%x (0 = dns_mitm re-read the hosts files)", rc);
    serviceClose(&srv);
}

/* ---- the update itself ---------------------------------------------------------------- */

static const char *const HOSTS_FILES[2] = {ATM "hosts/default.txt", ATM "hosts/emummc.txt"};

static void rotate_log(void) {
    struct stat st;
    if (stat(LOG_PATH, &st) == 0 && st.st_size > 200 * 1024) {
        remove(LOG_PATH ".1");
        rename(LOG_PATH, LOG_PATH ".1");
    }
}

/* One full cycle. stage: 0 all, N = stop before step N. Cleans up after itself. */
/* Returns false after a transient failure (network, bsd, ssl, fetch): the caller retries in 5 minutes. */
static bool cycle(int n, long stage) {
    bool transient = false;
    rotate_log();
    bool dry_file = file_exists(ATM "openpak-fetchd.dry");
    bool real = !dry_file && (file_exists(ATM "openpak-fetchd.auto") || file_exists(ATM "openpak-fetchd.write"));
    lg("---- cycle %d begin: mode=%s (writes need .auto or .write, and no .dry)", n, real ? "WRITE" : "DRY");

    NifmInternetConnectionType t = 0; NifmInternetConnectionStatus s = 0; u32 str = 0;
    Result rc = nifmGetInternetConnectionStatus(&t, &str, &s);
    if (R_FAILED(rc) || s != NifmInternetConnectionStatus_Connected) {
        lg("cycle %d: not connected (rc=0x%x status=%u), will retry", n, rc, (u32)s);
        return false;
    }
    if (stage && stage <= 1) { lg("stage limit: stopping before step 1"); return true; }
    if (!resolve()) { lg("step 1 dns: FAIL (no address), will retry"); return false; }

    if (stage && stage <= 2) { lg("stage limit: stopping before step 2"); return true; }
    int have_marker = 0, have_bsd = 0, have_ssl = 0;
    {
        FILE *mf = fopen(RUNNING_PATH, "wb");
        if (mf) { fputs("running\n", mf); fflush(mf); fclose(mf); }
        fsdevCommitDevice("sdmc");
        have_marker = mf != NULL;
        lg("running marker written=%d (removed only when the cycle finishes)", have_marker);
    }
    {
        BsdInitConfig cfg = *bsdGetDefaultInitConfig();
        cfg.tmem_buffer = g_bsd_tmem;
        cfg.tmem_buffer_size = sizeof(g_bsd_tmem);
        cfg.tcp_tx_buf_size = 0x8000;
        cfg.tcp_rx_buf_size = 0x10000;
        cfg.tcp_tx_buf_max_size = 0;
        cfg.tcp_rx_buf_max_size = 0;
        cfg.sb_efficiency = 1;
        lg("step 2 bsd: call bsdInitialize(version=%u tmem=%p/0x%x sessions=1 type=bsd:u)", cfg.version, cfg.tmem_buffer, (unsigned)cfg.tmem_buffer_size);
        heap_report("bsdInitialize");
        rc = bsdInitialize(&cfg, 1, BIT(0));
        char rt[64];
        lg("step 2 bsd: bsdInitialize rc=%s", rc_text(rc, rt, sizeof(rt)));
        if (R_FAILED(rc)) { transient = true; lg("step 2 bsd: FAIL, cycle skipped, retry in %llu s", RETRY_SECONDS); goto out; }
        have_bsd = 1;
    }

    if (stage && stage <= 3) { lg("stage limit: stopping before step 3"); goto out; }
    heap_report("sslInitialize");
    lg("step 3 fetch: call sslInitialize(1)");
    rc = sslInitialize(1);
    {
        char rt[64];
        lg("step 3 fetch: sslInitialize rc=%s", rc_text(rc, rt, sizeof(rt)));
    }
    if (R_FAILED(rc)) { transient = true; goto out; }
    have_ssl = 1;

    char err[200];
    char *body; size_t blen;
    long long high = read_num(VERSION_PATH, 0);
    long long nro_high = read_num(NRO_VERSION, 0);
    if (nro_high > high) high = nro_high;
    lg("step 3 fetch: highest ceiling version accepted so far = %lld (own file or the NRO's)", high);

    if (!https_get(PATH_CEILING, &body, &blen)) { lg("step 3 fetch: ceiling not fetched, nothing changes, retry in %llu s", RETRY_SECONDS); transient = true; goto out; }
    if (!fd_ceiling_check(body, blen, high, &g_ceil, err, sizeof(err))) { lg("REFUSED: %s; nothing changes", err); goto out; }
    lg("ceiling version %lld verified under the pinned key (%d switch families)", g_ceil.version, g_ceil.count);
    if (g_ceil.version > high) {
        char num[32];
        int nn = snprintf(num, sizeof(num), "%lld\n", g_ceil.version);
        mkdir(STATE_DIR, 0777);
        lg("state: call write %s", VERSION_PATH);
        if (write_plain(VERSION_PATH, num, (size_t)nn) != 0) { lg("REFUSED: cannot persist the accepted version; nothing changes"); goto out; }
    }

    if (!https_get(PATH_PROFILE, &body, &blen)) { lg("step 3 fetch: profile not fetched, nothing changes, retry in %llu s", RETRY_SECONDS); transient = true; goto out; }

    if (stage && stage <= 4) { lg("stage limit: stopping before step 4"); goto out; }
    {
        static char server[64];
        server[0] = '\0';
        FILE *f = fopen(SERVER_TXT, "rb");
        if (f) {
            if (fgets(server, sizeof(server), f)) server[strcspn(server, "\r\n")] = '\0';
            fclose(f);
        }
        fd_stats st;
        size_t bl = 0;
        if (!fd_build_block(body, blen, &g_ceil, server, g_block, sizeof(g_block), &bl, &st, err, sizeof(err))) {
            lg("REFUSED: %s; nothing changes", err);
            goto out;
        }
        lg("step 4 build: block %zu bytes, %d host lines from %d profile rules, server %s%s", bl, st.lines, st.rules, st.server, server[0] ? " (server.txt)" : "");
        if (st.dropped[0]) lg("left out (outside the signed ceiling, or not expressible in a hosts file): %s", st.dropped);

        if (stage && stage <= 5) { lg("stage limit: stopping before step 5"); goto out; }
        bool changed = false;
        if (!real) {
            mkdir(STATE_DIR, 0777);
            int w = write_plain(DRYBLOCK_PATH, g_block, bl);
            lg("step 5 dry: would-be block written to openpak-fetchd/dry-block.txt (rc=%d); hosts files are not touched", w);
        }
        int w = fd_update_hosts(HOSTS_FILES, 2, g_block, bl, fd_policy_patterns(), real, &changed, lg, commit_sd);
        if (w < 0) lg("step 5: refused, no hosts file was touched");
        else if (real) lg("step 5: %d hosts file(s) written", w);

        if (stage && stage <= 6) { lg("stage limit: stopping before step 6"); goto out; }
        bool force = file_exists(ATM "openpak-fetchd.reloadtest");
        if (changed || force) reload_dns_mitm();
        else lg("step 6: nothing was written, no dns_mitm reload needed");
    }
    lg("cycle %d done", n);

out:
    if (have_ssl) { lg("call sslExit"); sslExit(); }
    if (have_bsd) { lg("call bsdExit"); bsdExit(); lg("bsdExit returned"); }
    if (have_marker) {
        int r = remove(RUNNING_PATH);
        fsdevCommitDevice("sdmc");
        lg("running marker removed r=%d", r);
    }
    return !transient;
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    Result rc;

    for (int i = 0; i < 60 && !file_exists("sdmc:/atmosphere"); i++) sleep_s(1);
    int one_shot = file_exists(ATM "openpak-fetchd.enable");
    int is_auto = file_exists(ATM "openpak-fetchd.auto");
    if (!one_shot && !is_auto) return 0;

    lg("---- openpak-fetchd start v2 (tid 01FE000000000F00, libnx bsd cfg version 1) enable=%d auto=%d", one_shot, is_auto);
    {
        int ok = 0;
        for (int i = 0; i < 30 && !ok; i++) {
            FILE *f = fopen(LOG_PATH, "ab");
            if (f) { ok = 1; fclose(f); } else sleep_s(1);
        }
        lg("sd writable=%d, hos version %u.%u.%u", ok, HOSVER_MAJOR(hosversionGet()), HOSVER_MINOR(hosversionGet()), HOSVER_MICRO(hosversionGet()));
    }
    if (one_shot) {
        int r = remove(ATM "openpak-fetchd.enable");
        fsdevCommitDevice("sdmc");
        lg("enable file consumed (one-shot): remove r=%d, re-arm by uploading a new empty enable file", r);
    }
    if (file_exists(RUNNING_PATH)) {
        lg("previous run did not finish (marker %s exists): exiting without touching the network", RUNNING_PATH);
        return 0;
    }
    long stage = read_num(ATM "openpak-fetchd.stage", 0);
    long delay = read_num(ATM "openpak-fetchd.delay", 20);
    if (delay < 0 || delay > 3600) delay = 20;
    lg("stage=%ld (0=all, N=stop before step N) delay=%ld s", stage, delay);

    int nifm_ok = 0;
    for (int i = 0; i < 120 && !nifm_ok; i++) {
        if (i == 0) lg("call nifmInitialize(User)");
        rc = nifmInitialize(NifmServiceType_User);
        if (R_SUCCEEDED(rc)) nifm_ok = 1;
        else { if (i % 10 == 0) lg("nifmInitialize rc=0x%x (attempt %d)", rc, i); sleep_s(1); }
    }
    lg("nifmInitialize done ok=%d", nifm_ok);
    if (!nifm_ok) { lg("giving up: no nifm"); return 0; }

    int connected = 0, req_made = 0;
    u32 last_t = 99, last_s = 99; Result last_rc = 0xffffffff;
    NifmRequest req;
    for (int i = 0; i < 600 && !connected; i++) {
        NifmInternetConnectionType t = 0; NifmInternetConnectionStatus s = 0; u32 str = 0;
        rc = nifmGetInternetConnectionStatus(&t, &str, &s);
        if (rc != last_rc || (u32)t != last_t || (u32)s != last_s || i % 15 == 0) {
            lg("nifm status rc=0x%x type=%u status=%u strength=%u", rc, (u32)t, (u32)s, str);
            last_rc = rc; last_t = (u32)t; last_s = (u32)s;
        }
        if (R_SUCCEEDED(rc) && s == NifmInternetConnectionStatus_Connected) { connected = 1; break; }
        if (!req_made && i >= 45 && file_exists(ATM "openpak-fetchd.nifmreq")) {
            req_made = 1;
            lg("call nifmCreateRequest");
            rc = nifmCreateRequest(&req, true);
            lg("nifmCreateRequest rc=0x%x", rc);
            if (R_SUCCEEDED(rc)) { rc = nifmRequestSubmit(&req); lg("nifmRequestSubmit rc=0x%x", rc); }
        }
        sleep_s(2);
    }
    if (!connected) { lg("giving up: never connected"); goto end; }
    lg("connected; waiting %ld s", delay);
    sleep_s((u64)delay);
    lg("delay done");
    mkdir(STATE_DIR, 0777);

    bool ok = cycle(1, stage);
    if (stage) { lg("stage set: single cycle only"); goto end; }

    /* Then every 6 hours of uptime (monotonic tick). A cycle that finds the network down is
       retried every 5 minutes without waiting out the 6 hours. */
    for (int n = 2;; n++) {
        u64 wait = ok ? CYCLE_SECONDS : RETRY_SECONDS;     /* a failed cycle never loops tightly */
        for (;;) {
            u64 until = ms_now() + wait * 1000ULL;
            while (ms_now() < until) {
                sleep_s(60);
                if (file_exists(ATM "openpak-fetchd.stop")) { lg("stop file found: leaving"); goto end; }
            }
            NifmInternetConnectionType t = 0; NifmInternetConnectionStatus s = 0; u32 str = 0;
            if (R_SUCCEEDED(nifmGetInternetConnectionStatus(&t, &str, &s)) && s == NifmInternetConnectionStatus_Connected) break;
            wait = RETRY_SECONDS;
        }
        ok = cycle(n, 0);
    }

end:
    if (req_made) nifmRequestClose(&req);
    nifmExit();
    lg("---- openpak-fetchd end");
    return 0;
}
