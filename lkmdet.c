/*
 * lkmdet — non-root susfs LKM detector (arm64)
 *
 * Built from the audit of inforcqb/susfs4ksu-lkm (module "susfs_guard_lkm")
 * vs stock simonpunk/susfs4ksu. All probes are unprivileged syscalls and
 * world-readable files; run as adb shell (uid 2000) or as any app.
 *
 * P1 zero-ino placeholder records:
 *    The LKM filters getdents64 buffers POST-HOC. When an entire chunk is
 *    hidden it must return nonzero (else the caller reads early-EOF), so it
 *    emits a placeholder record: d_ino=0, empty name (sus_path.c:1612-1648).
 *    A clean kernel never produces one (procfs/sysfs inos are never 0) and
 *    built-in susfs never produces one (its filldir64 hook drops the entry
 *    before it reaches the user buffer). Deterministic trigger: raw
 *    getdents64 with a 56-byte buffer -> single-record chunks.
 * P2 mprotect/uaccess race:
 *    The filter's compaction runs under pagefault_disable(); on a uaccess
 *    fault it bails and returns the ORIGINAL unfiltered buffer
 *    (sus_path.c:1603-1609). A second thread flipping the buffer to
 *    PROT_NONE mid-syscall makes it fault; mprotect preserves content, so
 *    literal hidden names ("susfs_*") survive in the buffer. The toggler
 *    parks behind a seq-cst "settled" handshake before the parser reads,
 *    so no PROT_NONE state can be in flight while we touch the buffer.
 * P3 /proc/sys/kernel/tainted:
 *    The module has no taint-scrub code; an out-of-tree unsigned .ko sets
 *    O (bit 10) and E (bit 11) forever. Built-in susfs never taints.
 * P4 /proc/modules grep (normally filtered by an m_show kprobe).
 * P5 /proc/kallsyms grep: [susfs_guard_lkm] tag = LKM; bare susfs_* symbols
 *    = built-in susfs without CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS.
 * P6 O_PATH open + fstat consistency on /proc/susfs_* nodes.
 * P7 syscall latency medians (INFO): kprobe BRK hooks add ~1-2us.
 *
 * Two build modes from this one source:
 *   executable : clang ... -o lkmdet lkmdet.c              (main())
 *   JNI lib   : clang ... -shared -fPIC -DLKMDET_LIBRARY  (Android glue)
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#ifndef __NR_getdents64
#define __NR_getdents64 217
#endif
#ifndef __NR_statx
#define __NR_statx 291
#endif
#ifndef __NR_reboot
#define __NR_reboot 169
#endif
#ifndef __NR_gettid
#define __NR_gettid 178
#endif
#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef STATX_BASIC_STATS
#define STATX_BASIC_STATS 0x000007ff
#endif

#define BUF_BIG   65536
#define SMALL_BUF 56     /* < 2*min_reclen(32): forces single-record chunks */

struct d64rec {
	uint64_t d_ino;
	int64_t  d_off;
	uint16_t d_reclen;
	uint8_t  d_type;
	char     d_name[];
};

/* ---------- shared output sink + findings ---------- */

static FILE *g_out;   /* stdout in binary mode, memstream in JNI mode */

static int g_ph_total, g_race_hit, g_opath_weird, g_mod_hits, g_ks_lkm, g_ks_total;
static unsigned long long g_taint;
static int g_oot, g_unsign;
static double g_race_sec = 10.0;
static const char *g_extra_dirs[8];
static int g_nextra;

static void *xmalloc(size_t n)
{
	void *p = malloc(n);
	if (!p) { fprintf(stderr, "out of memory\n"); exit(1); }
	return p;
}

static double now_s(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static char *read_all(const char *path, size_t cap, size_t *out_len)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return NULL;
	char *buf = xmalloc(cap + 1);
	size_t len = 0;
	while (len < cap) {
		ssize_t r = read(fd, buf + len, cap - len);
		if (r <= 0) break;
		len += (size_t)r;
	}
	close(fd);
	buf[len] = 0;
	*out_len = len;
	return buf;
}

/* ---------------- P1: placeholder scan ---------------- */

/*
 * err      : errno of the first failing syscall/open, 0 if none
 * first_ret: return value of the first getdents64 call (diagnostics)
 */
static int scan_dirents(const char *path, size_t bufsz, unsigned long *recs,
			int *ph, int *fb, int *err, long *first_ret)
{
	int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	*err = 0;
	*first_ret = 0;
	if (fd < 0) {
		*err = errno;
		return -1;
	}
	static char buf[BUF_BIG];
	unsigned long r = 0;
	int p = 0;
	size_t cur = bufsz > sizeof(buf) ? sizeof(buf) : bufsz;
	int fallback = 0;
	int first = 1;

	for (;;) {
		long n = syscall(__NR_getdents64, fd, buf, cur);
		if (first) { *first_ret = n; first = 0; }
		if (n == 0) break;
		if (n < 0) {
			if (errno == EINVAL && cur < sizeof(buf)) {
				cur = 4096;
				fallback = 1;
				continue;
			}
			*err = errno;
			break;
		}
		long off = 0;
		while (off + (long)sizeof(struct d64rec) <= n) {
			struct d64rec *rec = (struct d64rec *)(void *)(buf + off);
			if (rec->d_reclen < (uint16_t)sizeof(struct d64rec) ||
			    off + (long)rec->d_reclen > n)
				break;
			if (rec->d_ino == 0 && rec->d_name[0] == '\0') {
				p++;
				if (p <= 8)
					fprintf(g_out,
						"    >> HIT zero-ino record: d_reclen=%u d_off=%lld d_type=%u\n",
						(unsigned)rec->d_reclen, (long long)rec->d_off,
						(unsigned)rec->d_type);
			}
			r++;
			off += (long)rec->d_reclen;
		}
	}
	close(fd);
	*recs = r;
	*ph = p;
	*fb = fallback;
	return 0;
}

static void probe_p1(void)
{
	g_ph_total = 0;
	const char *dirs[10];
	int nd = 0;
	dirs[nd++] = "/proc";
	dirs[nd++] = "/sys/module";
	for (int i = 0; i < g_nextra; i++)
		dirs[nd++] = g_extra_dirs[i];

	for (int i = 0; i < nd; i++) {
		unsigned long r1 = 0, r2 = 0;
		int p1 = 0, p2 = 0, fb1 = 0, fb2 = 0;
		int e1 = 0, e2 = 0;
		long fr1 = 0, fr2 = 0;

		if (scan_dirents(dirs[i], SMALL_BUF, &r1, &p1, &fb1, &e1, &fr1) != 0) {
			fprintf(g_out, "    %-14s open failed: %s\n", dirs[i], strerror(e1));
			continue;
		}
		fprintf(g_out, "    %-14s small-buf: %6lu records, %d zero-ino%s\n",
			dirs[i], r1, p1, fb1 ? " (EINVAL fallback engaged)" : "");
		if (r1 == 0 || e1 != 0)
			fprintf(g_out, "       (diag: first syscall returned %ld, errno=%d)\n", fr1, e1);

		scan_dirents(dirs[i], 32768, &r2, &p2, &fb2, &e2, &fr2);
		fprintf(g_out, "    %-14s big-buf : %6lu records, %d zero-ino%s\n",
			dirs[i], r2, p2, fb2 ? " (EINVAL fallback engaged)" : "");
		if (r2 == 0 || e2 != 0)
			fprintf(g_out, "       (diag: first syscall returned %ld, errno=%d)\n", fr2, e2);

		g_ph_total += p1 + p2;
	}
	fprintf(g_out, "%s\n", g_ph_total
		? "  >> PLACEHOLDER ORACLE HIT - post-hoc getdents filter present (LKM susfs fingerprint)"
		: "    no zero-ino records - consistent with clean kernel or built-in susfs");
}

/* ---------------- P2: mprotect/uaccess race ---------------- */

struct race_ctx {
	uint8_t *buf;
	size_t   len;
	atomic_int racing;
	atomic_int settled;
	atomic_int stop;
};

/*
 * Each toggle pair ends with PROT_READ|PROT_WRITE. When the toggler sees
 * racing cleared it parks and raises `settled`; from that instant no
 * mprotect can run until main arms racing again — so once main observes
 * settled (and re-arms RW itself), parsing the buffer is safe. Seq-cst
 * atomics make the flag protocol sequentially consistent.
 */
static void *toggler_fn(void *arg)
{
	struct race_ctx *c = arg;
	for (;;) {
		if (atomic_load(&c->stop))
			break;
		if (!atomic_load(&c->racing)) {
			atomic_store(&c->settled, 1);
			struct timespec ts = {0, 100000};
			nanosleep(&ts, NULL);
			continue;
		}
		mprotect(c->buf, c->len, PROT_NONE);
		mprotect(c->buf, c->len, PROT_READ | PROT_WRITE);
	}
	return NULL;
}

static int find_pat(const uint8_t *h, size_t n, const char *pat, size_t *off)
{
	size_t m = strlen(pat);
	if (n < m) return 0;
	const uint8_t *r = memmem(h, n, pat, m);
	if (r) { *off = (size_t)(r - h); return 1; }
	return 0;
}

static void dump_win(const uint8_t *buf, size_t n, size_t off)
{
	size_t s = off > 40 ? off - 40 : 0;
	size_t e = off + 80 < n ? off + 80 : n;
	fprintf(g_out, "    >> LEAKED bytes at +0x%zx: \"", off);
	for (size_t i = s; i < e; i++)
		fputc((buf[i] >= 32 && buf[i] < 127) ? buf[i] : '.', g_out);
	fputs("\"\n", g_out);
}

static int race_probe(const char *dir, double budget)
{
	int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(g_out, "    open %s failed: %s\n", dir, strerror(errno));
		return 0;
	}
	size_t len = BUF_BIG;
	uint8_t *buf = mmap(NULL, len, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED) { close(fd); return 0; }

	struct race_ctx ctx;
	ctx.buf = buf;
	ctx.len = len;
	atomic_init(&ctx.racing, 0);
	atomic_init(&ctx.settled, 1);
	atomic_init(&ctx.stop, 0);

	pthread_t th;
	if (pthread_create(&th, NULL, toggler_fn, &ctx) != 0) {
		munmap(buf, len);
		close(fd);
		return 0;
	}

	double t0 = now_s(), last = t0;
	unsigned long attempts = 0, faults = 0, ph = 0;
	int hit = 0;
	size_t hit_off = 0;

	while (now_s() - t0 < budget) {
		if (lseek(fd, 0, SEEK_SET) < 0) break;
		atomic_store(&ctx.settled, 0);
		atomic_store(&ctx.racing, 1);
		long n = syscall(__NR_getdents64, fd, buf, len);
		atomic_store(&ctx.racing, 0);
		int spins = 0;
		while (!atomic_load(&ctx.settled) && ++spins < 10000000)
			; /* toggler parks within one pair (~us) */
		mprotect(buf, len, PROT_READ | PROT_WRITE);

		attempts++;
		if (n < 0) { faults++; continue; }
		if (n == 0) continue;

		size_t off;
		if (find_pat(buf, (size_t)n, "susfs", &off) ||
		    find_pat(buf, (size_t)n, "guard_lkm", &off)) {
			hit = 1;
			hit_off = off;
			break;
		}
		/* bonus: placeholder records inside raced buffers */
		long o = 0;
		while (o + (long)sizeof(struct d64rec) <= n) {
			struct d64rec *rec = (struct d64rec *)(void *)(buf + o);
			if (rec->d_reclen < (uint16_t)sizeof(struct d64rec) ||
			    o + (long)rec->d_reclen > n)
				break;
			if (rec->d_ino == 0 && rec->d_name[0] == '\0')
				ph++;
			o += (long)rec->d_reclen;
		}

		double el = now_s() - t0;
		if (el - last >= 2.0) {
			fprintf(g_out, "    ... %lu attempts, %lu faults, %lu zero-ino records\n",
				attempts, faults, ph);
			last = el;
		}
	}
	atomic_store(&ctx.stop, 1);
	pthread_join(th, NULL);
	if (hit)
		dump_win(buf, len, hit_off);
	fprintf(g_out, "    attempts=%lu  faults=%lu  zero-ino-in-raced-bufs=%lu  leak=%s\n",
		attempts, faults, ph, hit ? "YES" : "no");
	munmap(buf, len);
	close(fd);
	return hit;
}

static void probe_p2(void)
{
	g_race_hit = 0;
	g_race_hit = race_probe("/proc", g_race_sec);
	if (g_race_hit)
		fprintf(g_out, "  >> LEAK ORACLE HIT - hidden names recovered from the buffer\n");
}

/* ---------------- P3: taint ---------------- */

static const char TAINT_LETTERS[] = "PFSRMBUWCIOELKAD";

static void probe_p3(void)
{
	g_taint = 0; g_oot = 0; g_unsign = 0;
	size_t len;
	char *b = read_all("/proc/sys/kernel/tainted", 64, &len);
	if (!b) {
		fprintf(g_out, "    unreadable: %s\n", strerror(errno));
		return;
	}
	unsigned long long v = strtoull(b, NULL, 0);
	g_taint = v;
	char letters[24];
	int li = 0;
	for (int i = 0; i < 16; i++)
		if ((v >> i) & 1ULL)
			letters[li++] = TAINT_LETTERS[i];
	letters[li] = 0;
	g_oot = (int)((v >> 10) & 1ULL);
	g_unsign = (int)((v >> 11) & 1ULL);
	fprintf(g_out, "    value=%llu (0x%llx)  flags='%s'%s%s\n",
		v, v, letters,
		g_oot ? "  [O = out-of-tree module loaded]" : "",
		g_unsign ? " [E = unsigned module loaded]" : "");
	free(b);
}

/* ---------------- P4/P5: file greps ---------------- */

static int grep_patterns(const char *path, const char *const *pats, size_t np,
			 int classify, unsigned cap, int *total_out)
{
	size_t len;
	char *b = read_all(path, (size_t)32 << 20, &len);
	if (!b) {
		fprintf(g_out, "    unreadable: %s\n", strerror(errno));
		*total_out = 0;
		return -1;
	}
	int hits = 0, printed = 0, tagged = 0;
	char *save = NULL;
	char *line = strtok_r(b, "\n", &save);
	while (line) {
		for (size_t i = 0; i < np; i++) {
			if (strstr(line, pats[i])) {
				hits++;
				int tag = (classify && strstr(line, "[susfs_guard_lkm]")) ? 1 : 0;
				if (tag) tagged++;
				if ((unsigned)printed < cap) {
					fprintf(g_out, "    >> %s%s\n", tag ? "[LKM-tag] " : "", line);
					printed++;
				}
				break;
			}
		}
		line = strtok_r(NULL, "\n", &save);
	}
	if (hits > (int)cap)
		fprintf(g_out, "    ... %d more matching lines\n", hits - (int)cap);
	fprintf(g_out, "    %d matching lines, %d module-tagged\n", hits, tagged);
	*total_out = hits;
	free(b);
	return tagged;
}

static void probe_p4(void)
{
	g_mod_hits = 0;
	const char *const pats[] = { "susfs", "guard_lkm", "sukisu" };
	int dummy = 0;
	int tagged = grep_patterns("/proc/modules", pats, 3, 0, 20, &dummy);
	if (tagged >= 0)
		g_mod_hits = dummy;
	fprintf(g_out, "%s\n", g_mod_hits
		? "  >> HIT - susfs module line present (filter degraded or absent)"
		: "    no susfs lines - consistent with clean, built-in, or filtered LKM");
}

static void probe_p5(void)
{
	g_ks_lkm = 0;
	g_ks_total = 0;
	const char *const pats[] = { "susfs_", "sus_path_", "sus_mount_",
				     "sus_map_", "sus_dirent_", "guard_lkm" };
	int total = 0;
	int tagged = grep_patterns("/proc/kallsyms", pats, 6, 1, 40, &total);
	if (tagged < 0)
		return;
	g_ks_lkm = tagged;
	g_ks_total = total;
	if (total > 0)
		fprintf(g_out, "  >> symbols visible: %d module-tagged (LKM), %d bare (built-in without CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS)\n",
			tagged, total - tagged);
	else
		fprintf(g_out, "    no susfs symbols - consistent with clean, hidden built-in, or filtered LKM\n");
}

/* ---------------- P6: O_PATH/fstat consistency ---------------- */

static const char *SUS_NODES[] = {
	"susfs_path", "susfs_kstat", "susfs_map", "susfs_uname",
	"susfs_avc_spoof", "susfs_enable_log", "susfs_hide_modules",
	"susfs_hide_mounts", "susfs_opath", "susfs_open_redirect",
	"susfs_spoof_cmdline", "susfs_variants",
};

static int opath_probe(void)
{
	int weird = 0;
	for (size_t i = 0; i < sizeof(SUS_NODES) / sizeof(*SUS_NODES); i++) {
		char path[128];
		snprintf(path, sizeof(path), "/proc/%s", SUS_NODES[i]);
		struct stat st;
		int stat_ok = (stat(path, &st) == 0);
		int fd = open(path, O_PATH | O_CLOEXEC);
		if (stat_ok && fd < 0) {
			fprintf(g_out, "    >> ODD %s: stat ok but open -> %s\n",
				path, strerror(errno));
			weird++;
		}
		if (fd < 0)
			continue;
		struct stat fst;
		if (fstat(fd, &fst) == 0) {
			fprintf(g_out, "    >> HIT %s: open(O_PATH) ok AND fstat ok (mode 0%o) - node visible\n",
				path, (unsigned)(fst.st_mode & 07777));
			weird++;
		} else if (errno == ENOENT) {
			fprintf(g_out, "    >> HIT %s: open(O_PATH) ok but fstat -> ENOENT (impossible on clean kernel; degraded LKM)\n",
				path);
			weird++;
		} else {
			fprintf(g_out, "    >> HIT %s: open ok, fstat -> %s\n",
				path, strerror(errno));
			weird++;
		}
		close(fd);
	}
	if (!weird)
		fprintf(g_out, "    all %zu nodes: consistent (ENOENT on every interface)\n",
			sizeof(SUS_NODES) / sizeof(*SUS_NODES));
	return weird;
}

static void probe_p6(void)
{
	g_opath_weird = 0;
	g_opath_weird = opath_probe();
}

/* ---------------- P7: syscall latency medians ---------------- */

static double bench(int which, int iters, int batches)
{
	static char statx_scratch[512];
	double *t = xmalloc((size_t)batches * sizeof(double));
	for (int bi = 0; bi < batches; bi++) {
		double t0 = now_s();
		for (int i = 0; i < iters; i++) {
			switch (which) {
			case 0: syscall(__NR_gettid); break;
			case 1: syscall(__NR_statx, AT_FDCWD, "/", 0, STATX_BASIC_STATS, statx_scratch); break;
			default: syscall(__NR_reboot, 0xDEADBEEF, 0xFAFAFAFA, 0, 0); break;
			}
		}
		t[bi] = (now_s() - t0) / iters * 1e9;
	}
	for (int i = 1; i < batches; i++) {
		double k = t[i];
		int j = i - 1;
		while (j >= 0 && t[j] > k) { t[j + 1] = t[j]; j--; }
		t[j + 1] = k;
	}
	double med = t[batches / 2];
	free(t);
	return med;
}

static void probe_p7(void)
{
	double t0 = bench(0, 20000, 24);
	double t1 = bench(1, 20000, 24);
#ifdef LKMDET_LIBRARY
	/* App sandbox seccomp kills any app calling reboot(2) with SIGSYS
	 * (tombstone 2026-10-14: "seccomp prevented call to disallowed arm64
	 * system call 142"). Never issue it from JNI; adb shell is fine. */
	fprintf(g_out, "    gettid        ~%6.0f ns (control)\n", t0);
	fprintf(g_out, "    statx '/'     ~%6.0f ns\n", t1);
	fprintf(g_out, "    reboot(2): not probed - Android seccomp SIGSYS-kills apps that\n"
	              "    call it. statx is hooked by the LKM too, so the timing pair above\n"
	              "    still carries the kprobe signal.\n");
#else
	long rb = syscall(__NR_reboot, 0xDEADBEEF, 0xFAFAFAFA, 0, 0);
	if (rb == -1 && errno == EPERM) {
		double t2 = bench(2, 20000, 24);
		fprintf(g_out, "    gettid        ~%6.0f ns (control)\n", t0);
		fprintf(g_out, "    statx '/'     ~%6.0f ns\n", t1);
		fprintf(g_out, "    reboot(magic) ~%6.0f ns (EPERM as expected)\n", t2);
		fprintf(g_out, "    note: kprobe hooks add ~1-2us per call on the LKM\n");
	} else {
		fprintf(g_out, "    gettid ~%.0f ns; statx ~%.0f ns; reboot probe returned %ld errno=%d - timing skipped\n",
			t0, t1, rb, errno);
	}
#endif
}

/* ---------------- banner + verdict ---------------- */

static void print_banner(void)
{
	struct utsname u;
	uname(&u);
	fprintf(g_out, "uid=%u  kernel=%s\n", (unsigned)getuid(), u.release);
	if (getuid() == 0)
		fprintf(g_out, "NOTE: running as root - the LKM's self-hide rules do not apply to uid 0.\n"
			       "      Run unprivileged (adb shell / app) for a real detection test.\n");
}

static void print_verdict(void)
{
	int lkm = g_ph_total || g_race_hit || g_opath_weird || g_ks_lkm > 0 || g_mod_hits;
	if (lkm) {
		fprintf(g_out, "susfs LKM DETECTED (non-root):\n");
		if (g_ph_total)
			fprintf(g_out, "  - %d zero-ino placeholder record(s) from the post-hoc getdents filter\n", g_ph_total);
		if (g_race_hit)
			fprintf(g_out, "  - hidden name bytes leaked through the uaccess race\n");
		if (g_opath_weird)
			fprintf(g_out, "  - %d O_PATH/fstat impossible state(s)\n", g_opath_weird);
		if (g_ks_lkm > 0)
			fprintf(g_out, "  - [susfs_guard_lkm]-tagged symbols in kallsyms\n");
		if (g_mod_hits)
			fprintf(g_out, "  - susfs line(s) in /proc/modules\n");
	} else if (g_ks_total > 0) {
		fprintf(g_out, "No LKM, BUT bare susfs_* kernel symbols visible in kallsyms\n"
			       "  = BUILT-IN susfs without CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS.\n"
			       "  Fix the kernel defconfig; an app can detect this today.\n");
	} else if (g_oot || g_unsign) {
		fprintf(g_out, "No direct LKM hit, but taint flags O/E say an out-of-tree/unsigned\n"
			       "module is loaded - susfs LKM is the prime suspect (it never scrubs taint).\n");
	} else {
		fprintf(g_out, "No susfs LKM detected. A clean kernel and a properly hidden BUILT-IN\n"
			       "susfs look identical here - no non-root oracle separates them, which is\n"
			       "exactly the built-in-vs-LKM argument.\n");
	}
}

/* ---------------- binary mode ---------------- */

#ifndef LKMDET_LIBRARY

int main(int argc, char **argv)
{
	signal(SIGPIPE, SIG_IGN);
	g_out = stdout;
	setvbuf(stdout, NULL, _IONBF, 0);

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-r") && i + 1 < argc)
			g_race_sec = atof(argv[++i]);
		else if (!strcmp(argv[i], "-d") && i + 1 < argc && g_nextra < 8)
			g_extra_dirs[g_nextra++] = argv[++i];
		else if (!strcmp(argv[i], "-q"))
			g_race_sec = 2.0;
	}

	fprintf(g_out, "=== lkmdet: non-root susfs LKM detector ===\n");
	print_banner();

	fprintf(g_out, "\n[P1] placeholder scan (raw getdents64, zero-ino records)\n");
	probe_p1();
	fprintf(g_out, "\n[P2] mprotect/uaccess race on getdents64(/proc), budget %.0fs\n", g_race_sec);
	probe_p2();
	fprintf(g_out, "\n[P3] /proc/sys/kernel/tainted\n");
	probe_p3();
	fprintf(g_out, "\n[P4] /proc/modules grep\n");
	probe_p4();
	fprintf(g_out, "\n[P5] /proc/kallsyms symbol grep\n");
	probe_p5();
	fprintf(g_out, "\n[P6] O_PATH/fstat consistency on /proc/susfs_* nodes\n");
	probe_p6();
	fprintf(g_out, "\n[P7] syscall latency medians (INFO - compare vs clean baseline)\n");
	probe_p7();
	fprintf(g_out, "\n=== VERDICT ===\n");
	print_verdict();
	return 0;
}

/* ---------------- JNI mode ---------------- */

#else
#include <jni.h>

static jstring run_probe_jni(JNIEnv *env, void (*fn)(void))
{
	char *mbuf = NULL;
	size_t mlen = 0;
	FILE *m = open_memstream(&mbuf, &mlen);
	if (!m)
		return (*env)->NewStringUTF(env, "(internal: memstream failed)");
	FILE *prev = g_out;
	g_out = m;
	fn();
	fclose(m);
	g_out = prev;
	jstring s = (*env)->NewStringUTF(env, mbuf ? mbuf : "");
	free(mbuf);
	return s;
}

static void run_banner(void)  { print_banner(); }
static void run_p1(void)      { probe_p1(); }
static void run_p2(void)      { probe_p2(); }
static void run_p3(void)      { probe_p3(); }
static void run_p4(void)      { probe_p4(); }
static void run_p5(void)      { probe_p5(); }
static void run_p6(void)      { probe_p6(); }
static void run_p7(void)      { probe_p7(); }
static void run_verdict(void) { print_verdict(); }

JNIEXPORT jstring JNICALL
Java_com_wildkernels_lkmdetector_MainActivity_nativeBanner(JNIEnv *env, jobject th)
{ (void)th; return run_probe_jni(env, run_banner); }

JNIEXPORT jstring JNICALL
Java_com_wildkernels_lkmdetector_MainActivity_nativeP1(JNIEnv *env, jobject th)
{ (void)th; return run_probe_jni(env, run_p1); }

JNIEXPORT jstring JNICALL
Java_com_wildkernels_lkmdetector_MainActivity_nativeP2(JNIEnv *env, jobject th, jint secs)
{ (void)th; g_race_sec = (secs > 0 && secs <= 120) ? (double)secs : 10.0; return run_probe_jni(env, run_p2); }

JNIEXPORT jstring JNICALL
Java_com_wildkernels_lkmdetector_MainActivity_nativeP3(JNIEnv *env, jobject th)
{ (void)th; return run_probe_jni(env, run_p3); }

JNIEXPORT jstring JNICALL
Java_com_wildkernels_lkmdetector_MainActivity_nativeP4(JNIEnv *env, jobject th)
{ (void)th; return run_probe_jni(env, run_p4); }

JNIEXPORT jstring JNICALL
Java_com_wildkernels_lkmdetector_MainActivity_nativeP5(JNIEnv *env, jobject th)
{ (void)th; return run_probe_jni(env, run_p5); }

JNIEXPORT jstring JNICALL
Java_com_wildkernels_lkmdetector_MainActivity_nativeP6(JNIEnv *env, jobject th)
{ (void)th; return run_probe_jni(env, run_p6); }

JNIEXPORT jstring JNICALL
Java_com_wildkernels_lkmdetector_MainActivity_nativeP7(JNIEnv *env, jobject th)
{ (void)th; return run_probe_jni(env, run_p7); }

JNIEXPORT jstring JNICALL
Java_com_wildkernels_lkmdetector_MainActivity_nativeVerdict(JNIEnv *env, jobject th)
{ (void)th; return run_probe_jni(env, run_verdict); }
#endif
