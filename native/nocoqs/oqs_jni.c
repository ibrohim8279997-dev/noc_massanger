/* Thin JNI bridge to liboqs ML-DSA-65. No cryptography here: three calls and memory hygiene. */
#include <jni.h>
#include <oqs/oqs.h>
#include <stdlib.h>
#include <string.h>

#define ALG OQS_SIG_alg_ml_dsa_65

/* returns publicKey || secretKey, or null */
JNIEXPORT jbyteArray JNICALL Java_noc_crypto_MlDsa65_nativeKeypair(JNIEnv *env, jclass cls) {
    OQS_SIG *s = OQS_SIG_new(ALG);
    if (!s) return NULL;
    size_t pl = s->length_public_key, sl = s->length_secret_key;
    uint8_t *buf = malloc(pl + sl);
    jbyteArray out = NULL;
    if (buf && OQS_SIG_keypair(s, buf, buf + pl) == OQS_SUCCESS) {
        out = (*env)->NewByteArray(env, (jsize)(pl + sl));
        if (out) (*env)->SetByteArrayRegion(env, out, 0, (jsize)(pl + sl), (jbyte *)buf);
    }
    if (buf) { OQS_MEM_cleanse(buf, pl + sl); free(buf); }
    OQS_SIG_free(s);
    return out;
}

JNIEXPORT jbyteArray JNICALL Java_noc_crypto_MlDsa65_nativeSign(JNIEnv *env, jclass cls, jbyteArray sk, jbyteArray msg) {
    OQS_SIG *s = OQS_SIG_new(ALG);
    if (!s) return NULL;
    jsize skl = (*env)->GetArrayLength(env, sk), ml = (*env)->GetArrayLength(env, msg);
    jbyteArray out = NULL;
    if ((size_t)skl == s->length_secret_key) {
        jbyte *skp = (*env)->GetByteArrayElements(env, sk, NULL);
        jbyte *mp = (*env)->GetByteArrayElements(env, msg, NULL);
        uint8_t *sig = malloc(s->length_signature);
        size_t sl = 0;
        if (sig && OQS_SIG_sign(s, sig, &sl, (const uint8_t *)mp, (size_t)ml, (const uint8_t *)skp) == OQS_SUCCESS) {
            out = (*env)->NewByteArray(env, (jsize)sl);
            if (out) (*env)->SetByteArrayRegion(env, out, 0, (jsize)sl, (jbyte *)sig);
        }
        free(sig);
        (*env)->ReleaseByteArrayElements(env, sk, skp, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, msg, mp, JNI_ABORT);
    }
    OQS_SIG_free(s);
    return out;
}

JNIEXPORT jboolean JNICALL Java_noc_crypto_MlDsa65_nativeVerify(JNIEnv *env, jclass cls, jbyteArray pk, jbyteArray msg, jbyteArray sig) {
    OQS_SIG *s = OQS_SIG_new(ALG);
    if (!s) return JNI_FALSE;
    jsize pl = (*env)->GetArrayLength(env, pk), ml = (*env)->GetArrayLength(env, msg), sl = (*env)->GetArrayLength(env, sig);
    jboolean ok = JNI_FALSE;
    if ((size_t)pl == s->length_public_key && sl > 0 && (size_t)sl <= s->length_signature) {
        jbyte *pp = (*env)->GetByteArrayElements(env, pk, NULL);
        jbyte *mp = (*env)->GetByteArrayElements(env, msg, NULL);
        jbyte *sp = (*env)->GetByteArrayElements(env, sig, NULL);
        ok = OQS_SIG_verify(s, (const uint8_t *)mp, (size_t)ml, (const uint8_t *)sp, (size_t)sl, (const uint8_t *)pp) == OQS_SUCCESS ? JNI_TRUE : JNI_FALSE;
        (*env)->ReleaseByteArrayElements(env, pk, pp, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, msg, mp, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, sig, sp, JNI_ABORT);
    }
    OQS_SIG_free(s);
    return ok;
}
