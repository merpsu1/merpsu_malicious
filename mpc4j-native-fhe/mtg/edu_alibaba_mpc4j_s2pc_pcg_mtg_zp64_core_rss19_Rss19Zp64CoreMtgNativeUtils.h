/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class edu_alibaba_mpc4j_s2pc_pcg_mtg_zp64_core_rss19_Rss19Zp64CoreMtgNativeUtils */

#ifndef _Included_edu_alibaba_mpc4j_s2pc_pcg_mtg_zp64_core_rss19_Rss19Zp64CoreMtgNativeUtils
#define _Included_edu_alibaba_mpc4j_s2pc_pcg_mtg_zp64_core_rss19_Rss19Zp64CoreMtgNativeUtils
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     edu_alibaba_mpc4j_s2pc_pcg_mtg_zp64_core_rss19_Rss19Zp64CoreMtgNativeUtils
 * Method:    checkCreatePlainModulus
 * Signature: (II)J
 */
JNIEXPORT jlong JNICALL Java_edu_alibaba_mpc4j_s2pc_pcg_mtg_zp64_core_rss19_Rss19Zp64CoreMtgNativeUtils_checkCreatePlainModulus
  (JNIEnv *, jclass, jint, jint);

/*
 * Class:     edu_alibaba_mpc4j_s2pc_pcg_mtg_zp64_core_rss19_Rss19Zp64CoreMtgNativeUtils
 * Method:    keyGen
 * Signature: (IJ)Ljava/util/ArrayList;
 */
JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pcg_mtg_zp64_core_rss19_Rss19Zp64CoreMtgNativeUtils_keyGen
  (JNIEnv *, jclass, jint, jlong);

/*
 * Class:     edu_alibaba_mpc4j_s2pc_pcg_mtg_zp64_core_rss19_Rss19Zp64CoreMtgNativeUtils
 * Method:    encryption
 * Signature: ([B[B[B[J[J)Ljava/util/ArrayList;
 */
JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pcg_mtg_zp64_core_rss19_Rss19Zp64CoreMtgNativeUtils_encryption
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jlongArray, jlongArray);

/*
 * Class:     edu_alibaba_mpc4j_s2pc_pcg_mtg_zp64_core_rss19_Rss19Zp64CoreMtgNativeUtils
 * Method:    decryption
 * Signature: ([B[B[B)[J
 */
JNIEXPORT jlongArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pcg_mtg_zp64_core_rss19_Rss19Zp64CoreMtgNativeUtils_decryption
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     edu_alibaba_mpc4j_s2pc_pcg_mtg_zp64_core_rss19_Rss19Zp64CoreMtgNativeUtils
 * Method:    computeResponse
 * Signature: ([B[B[B[J[J[J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pcg_mtg_zp64_core_rss19_Rss19Zp64CoreMtgNativeUtils_computeResponse
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jlongArray, jlongArray, jlongArray);

#ifdef __cplusplus
}
#endif
#endif
