/* libwild - JNI bridge for the Native Detector app (com.reveny.nativecheck).
 *
 * The app is upstream reveny code, untouched; this library fills its
 * detection placeholder (Native.getDetections) with the wilddet engine,
 * which ports the detection surface of Uber Driver 4.602.10001
 * (DEX/RootBeer constants + libse.so native mechanisms). See wilddet.c.
 *
 * Single translation unit: we #include the engine so its static state
 * (g_results, g_count) is directly reachable here.
 */
#include <jni.h>

#include "wilddet.c"

/* desc = explanation + blank line + evidence (what / more info / proof) */
static char *join_desc(const char *expl, const char *ev)
{
    if (!ev || !ev[0])
        return strdup(expl);
    size_t n = strlen(expl) + strlen(ev) + 4;
    char *s = malloc(n);
    if (!s)
        return strdup(expl);
    snprintf(s, n, "%s\n\n%s", expl, ev);
    return s;
}

JNIEXPORT jobjectArray JNICALL
Java_com_reveny_nativecheck_app_Native_getDetections(JNIEnv *env, jobject thiz,
        jobject context, jobject pm, jboolean experimental)
{
    (void)thiz; (void)context; (void)pm;

    int flags = (experimental == JNI_TRUE) ? WD_EXPERIMENTAL : 0;
    int count = wilddet_run(flags);

    jclass dcls = (*env)->FindClass(env, "com/reveny/nativecheck/app/DetectionData");
    if (!dcls)
        return NULL;
    /* DetectionData(name, description, group) */
    jmethodID ctor = (*env)->GetMethodID(env, dcls, "<init>",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
    if (!ctor)
        return NULL;

    jobjectArray arr = (*env)->NewObjectArray(env, count, dcls, NULL);
    if (!arr) {
        wilddet_free();
        return NULL;
    }

    for (int i = 0; i < count; i++) {
        const char *desc = wilddet_desc(i);
        const char *ev = wilddet_evidence(i);
        char *full = join_desc(desc, ev);

        jstring jn = (*env)->NewStringUTF(env, wilddet_name(i));
        jstring jd = (*env)->NewStringUTF(env, full ? full : desc);
        jstring jg = (*env)->NewStringUTF(env, wilddet_group(i));

        jobject o = (*env)->NewObject(env, dcls, ctor, jn, jd, jg);
        if (o)
            (*env)->SetObjectArrayElement(env, arr, i, o);

        (*env)->DeleteLocalRef(env, jn);
        (*env)->DeleteLocalRef(env, jd);
        (*env)->DeleteLocalRef(env, jg);
        if (o)
            (*env)->DeleteLocalRef(env, o);
        free(full);
    }

    wilddet_free();
    return arr;
}
