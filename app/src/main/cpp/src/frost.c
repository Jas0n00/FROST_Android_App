#include <jni.h>
#include <android/log.h>
#include <openssl/bn.h>
#include <stdlib.h>
#include "../headers/signing.h"
#include "../headers/globals.h"

#define LOG_TAG "NativeFrost"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)


extern void execute_signing(int threshold, int participants, const char* message, int* indices);
extern bool verify_signing(const char* message, int index);

// JNI function to execute signing and return hex strings
JNIEXPORT void JNICALL
Java_cz_but_myapplication_MainActivity_executeSigning(JNIEnv *env, jobject thiz, jint threshold,
                                                      jint participants, jstring message,
                                                      jintArray indices) {
    LOGI("Starting signing process in JNI");

    // Convert jstring message to C string
    const char *nativeMessage = (*env)->GetStringUTFChars(env, message, NULL);
    if (nativeMessage == NULL) {
        LOGE("Failed to convert message string");
        return;
    }

    // Convert jintArray to int array
    jint *nativeIndices = (*env)->GetIntArrayElements(env, indices, NULL);
    if (nativeIndices == NULL) {
        LOGE("Failed to convert indices array");
        (*env)->ReleaseStringUTFChars(env, message, nativeMessage);
        return;
    }

    // Call the execute_signing function to perform the signing process
    execute_signing(threshold, participants, nativeMessage, nativeIndices);

    // Now that the signing is done, the global_signature and global_hash should be populated

    // Get the MainActivity class
    jclass mainActivityClass = (*env)->GetObjectClass(env, thiz);

    // Find the onSigningCompleted method
    jmethodID method = (*env)->GetMethodID(env, mainActivityClass, "onSigningCompleted", "(Ljava/lang/String;Ljava/lang/String;)V");

    if (method != NULL) {
        // Create the Java strings to pass to the method
        jstring signatureJStr = (*env)->NewStringUTF(env, global_signature);
        jstring hashJStr = (*env)->NewStringUTF(env, global_hash);

        // Call the method on the MainActivity object (thiz)
        (*env)->CallVoidMethod(env, thiz, method, signatureJStr, hashJStr);
    } else {
        LOGE("Method onSigningCompleted not found");
    }

    // Release the memory
    (*env)->ReleaseStringUTFChars(env, message, nativeMessage);
    (*env)->ReleaseIntArrayElements(env, indices, nativeIndices, 0);
}

JNIEXPORT jboolean JNICALL
Java_cz_but_myapplication_MainActivity_verifySignature(JNIEnv *env, jobject thiz, jstring jMessage,
                                                       jintArray jIndices) {
    const char* message = (*env)->GetStringUTFChars(env, jMessage, NULL);
    jint* indices = (*env)->GetIntArrayElements(env, jIndices, NULL);
    jsize num_indices = (*env)->GetArrayLength(env, jIndices);

    // Iterate over indices
    for (jsize i = 0; i < num_indices; i++) {
        int index = indices[i];
        if (!verify_signing(message, index)) {
            // Cleanup and return failure
            (*env)->ReleaseStringUTFChars(env, jMessage, message);
            (*env)->ReleaseIntArrayElements(env, jIndices, indices, 0);
            return JNI_FALSE; // Verification failed
        }
    }

    // Cleanup and return success
    (*env)->ReleaseStringUTFChars(env, jMessage, message);
    (*env)->ReleaseIntArrayElements(env, jIndices, indices, 0);
    return JNI_TRUE; // All verifications succeeded
}