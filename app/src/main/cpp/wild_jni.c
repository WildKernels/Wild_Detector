/* libwild - JNI bridge for the Native Detector app (com.reveny.nativecheck).
 *
 * The app is upstream reveny code, untouched; this library fills its
 * detection placeholder (Native.getDetections) with the WildKernels
 * engine that detects the susfs4ksu-lkm loadable-module port.
 *
 * Single translation unit: we #include the engine so its static state
 * (g_out, probe globals) is directly reachable here.
 */
#include "lkmdet.c"

/* run a probe with its stdout captured, mirroring run_probe_jni() */
static char *capture_text(void (*fn)(void))
{
    char *mbuf = NULL;
    size_t mlen = 0;
    FILE *m = open_memstream(&mbuf, &mlen);
    if (!m)
        return strdup("");
    FILE *prev = g_out;
    g_out = m;
    fn();
    fclose(m);
    g_out = prev;
    if (!mbuf)
        return strdup("");
    return mbuf;
}

/* pull only the ">>" evidence lines out of a probe report */
static char *evidence_lines(const char *report)
{
    size_t cap = 4096, used = 0;
    char *out = malloc(cap);
    if (!out)
        return strdup("");
    out[0] = 0;
    const char *p = report;
    while (*p) {
        const char *e = strchr(p, '\n');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        const char *t = p;
        size_t tlen = len;
        while (tlen && (*t == ' ' || *t == '\t')) { t++; tlen--; }
        if (tlen >= 2 && t[0] == '>' && t[1] == '>') {
            if (used + len + 2 > cap) {
                cap = (used + len + 2) * 2;
                char *n = realloc(out, cap);
                if (!n)
                    break;
                out = n;
            }
            memcpy(out + used, p, len);
            used += len;
            out[used++] = '\n';
            out[used] = 0;
        }
        if (!e)
            break;
        p = e + 1;
    }
    return out;
}

static char *join_desc(const char *expl, const char *ev)
{
    size_t n = strlen(expl) + strlen(ev) + 4;
    char *s = malloc(n);
    if (!s)
        return strdup(expl);
    snprintf(s, n, "%s\n\n%s", expl, ev);
    return s;
}

static void add_entry(JNIEnv *env, jobjectArray arr, int idx, jclass dcls,
                      jmethodID ctor, const char *name, const char *expl,
                      const char *report)
{
    char *ev = evidence_lines(report);
    char *desc = join_desc(expl, ev);
    jstring jn = (*env)->NewStringUTF(env, name);
    jstring jd = (*env)->NewStringUTF(env, desc);
    jobject o = (*env)->NewObject(env, dcls, ctor, jn, jd);
    (*env)->SetObjectArrayElement(env, arr, idx, o);
    free(ev);
    free(desc);
}

JNIEXPORT jobjectArray JNICALL
Java_com_reveny_nativecheck_app_Native_getDetections(JNIEnv *env, jobject thiz,
        jobject context, jobject pm, jboolean experimental)
{
    (void)thiz; (void)context; (void)pm; (void)experimental;

    /* the two probes that actually detect the LKM (per the susfs audit);
     * the SELinux-blocked file reads never fire for app uids, so they are
     * not part of the app flow */
    g_race_sec = 10.0;
    char *p2r = capture_text(probe_p2);
    char *p6r = capture_text(probe_p6);
    int hit2 = probe_result_class(2);
    int hit6 = probe_result_class(6);

    int count = (hit2 ? 1 : 0) + (hit6 ? 1 : 0);

    jclass dcls = (*env)->FindClass(env, "com/reveny/nativecheck/app/DetectionData");
    if (!dcls) {
        free(p2r); free(p6r);
        return NULL;
    }
    jmethodID ctor = (*env)->GetMethodID(env, dcls, "<init>",
                                         "(Ljava/lang/String;Ljava/lang/String;)V");
    if (!ctor) {
        free(p2r); free(p6r);
        return NULL;
    }
    jobjectArray arr = (*env)->NewObjectArray(env, count, dcls, NULL);

    int i = 0;
    if (hit2) {
        add_entry(env, arr, i++, dcls, ctor,
                  "susfs4ksu-lkm: getdents64 race leak",
                  "The loadable susfs module hides its /proc entries from "
                  "directory listings, but the hidden names leak out of the "
                  "kernel's getdents64 buffer during an mprotect/uaccess race.",
                  p2r);
    }
    if (hit6) {
        add_entry(env, arr, i++, dcls, ctor,
                  "susfs4ksu-lkm: /proc O_PATH inconsistency",
                  "The LKM's hiding layer fails open: /proc/susfs_* entries "
                  "pass open(O_PATH) but fstat reports ENOENT, which is "
                  "impossible on a clean kernel.",
                  p6r);
    }

    free(p2r);
    free(p6r);
    return arr;
}
