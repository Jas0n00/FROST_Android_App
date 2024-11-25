#include "../boringssl/include/openssl/bn.h"
#include "../boringssl/include/openssl/crypto.h"  // For OpenSSL initialization
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <android/log.h>
#include "../headers/setup.h"
#include "../headers/signing.h"
#include "../headers/globals.h"

#define LOG_TAG "NativeFrost"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)



// Function to initialize participants
// Your initialization function
participant* initialize_participants(int threshold, int participants) {
    LOGI("Initializing participants: threshold = %d, participants = %d", threshold, participants);

    participant* p = (participant*)malloc(participants * sizeof(participant));
    if (p == NULL) {
        LOGE("Memory allocation for participants failed");
        return NULL;
    }

    for (int i = 0; i < participants; i++) {
        p[i].index = i;
        p[i].threshold = threshold;
        p[i].participants = participants;
        p[i].pub_commit = NULL;
        p[i].rcvd_commit_head = NULL;
        p[i].rcvd_sec_share_head = NULL;
        LOGI("Participant %d initialized: threshold = %d, participants = %d", i, threshold, participants);
    }

    // Store participants globally
    global_participants = p;
    global_participants_count = participants;

    return p;
}


// Function to initialize public commitments
pub_commit_packet** initialize_pub_commits(participant* p, int participants) {
    LOGI("Initializing public commitments for %d participants", participants);
    pub_commit_packet** pub_commits = (pub_commit_packet**)malloc(participants * sizeof(pub_commit_packet*));
    if (pub_commits == NULL) {
        LOGE("Memory allocation for public commitments failed");
        return NULL; // Memory allocation failed
    }

    for (int i = 0; i < participants; i++) {
        pub_commits[i] = init_pub_commit(&p[i]);
        LOGI("Public commitment initialized for participant %d", i);
    }

    return pub_commits;
}

// Function to initialize the threshold set
participant* initialize_threshold_set(int threshold, participant* p, int* indices) {
    LOGI("Initializing threshold set: threshold = %d", threshold);
    participant* threshold_set = (participant*)malloc(threshold * sizeof(participant));
    if (threshold_set == NULL) {
        LOGE("Memory allocation for threshold set failed");
        return NULL; // Memory allocation failed
    }

    for (int i = 0; i < threshold; i++) {
        threshold_set[i] = p[indices[i]];
        LOGI("Threshold set participant %d: index = %d", i, indices[i]);
    }

    return threshold_set;
}

char* bn_to_hex_string(BIGNUM* bn) {
    char* hex_str = BN_bn2hex(bn);
    if (hex_str == NULL) {
        return NULL;
    }
    return hex_str;
}

void store_signature_and_hash(signature_packet sig) {
    // Free any previously stored values (using OpenSSL_free)
    if (global_signature != NULL) {
        OPENSSL_free(global_signature);
    }
    if (global_hash != NULL) {
        OPENSSL_free(global_hash);
    }

    char* signature_hex = bn_to_hex_string(sig.signature);
    char* hash_hex = bn_to_hex_string(sig.hash);

    // Use OPENSSL_strdup to allocate memory and copy the strings
    global_signature = OPENSSL_strdup(signature_hex);  // Allocate memory and copy the signature string
    if (global_signature == NULL) {
        LOGE("Failed to allocate memory for signature");
        return;  // Handle memory allocation failure if needed
    }

    global_hash = OPENSSL_strdup(hash_hex);  // Allocate memory and copy the hash string
    if (global_hash == NULL) {
        LOGE("Failed to allocate memory for hash");
        OPENSSL_free(global_signature);  // Clean up previously allocated memory
        return;  // Handle memory allocation failure if needed
    }
}

// Function to perform signing process
void perform_signing(int threshold, int participants, const char* message, int* indices) {
    LOGI("Starting signing process: threshold = %d, participants = %d", threshold, participants);

    participant* p = initialize_participants(threshold, participants);
    if (p == NULL) return;

    pub_commit_packet** pub_commits = initialize_pub_commits(p, participants);
    if (pub_commits == NULL) {
        free(p);
        return;
    }

    // Simulate broadcasting the public commitments to all other participants
    LOGI("Broadcasting public commitments to all participants");
    for (int i = 0; i < participants; i++) {
        for (int j = 0; j < participants; j++) {
            if (i != j) {
                LOGI("Participant %d accepts public commitment from participant %d", i, j);
                accept_pub_commit(&p[i], pub_commits[j]);
            }
        }
    }

    // Initialize and exchange secret shares
    LOGI("Exchanging secret shares between participants");
    for (int i = 0; i < participants; i++) {
        BIGNUM* self_share = init_sec_share(&p[i], p[i].index);
        LOGI("Participant %d generated self-secret share", i);
        accept_sec_share(&p[i], p[i].index, self_share);

        for (int j = 0; j < participants; j++) {
            if (i != j) {
                BIGNUM* sec_share = init_sec_share(&p[i], p[j].index);
                LOGI("Participant %d generated secret share for participant %d", i, j);
                accept_sec_share(&p[j], p[i].index, sec_share);
            }
        }
    }

    // Generate keys for all participants
    LOGI("Generating keys for all participants");
    for (int i = 0; i < participants; i++) {
        gen_keys(&p[i]);
    }

    // Create threshold set
    participant* threshold_set = initialize_threshold_set(threshold, p, indices);
    if (threshold_set == NULL) {
        free(p);
        free(pub_commits);
        return;
    }

    // Initialize public share commitments for chosen participants
    aggregator agg = { .threshold = threshold, .rcvd_pub_share_head = NULL };
    pub_share_packet** pub_shares = (pub_share_packet**)malloc(threshold * sizeof(pub_share_packet*));
    if (pub_shares == NULL) {
        LOGE("Memory allocation for public shares failed");
        free(p);
        free(pub_commits);
        free(threshold_set);
        return;
    }

    for (int i = 0; i < threshold; i++) {
        pub_shares[i] = init_pub_share(&threshold_set[i]);
        accept_pub_share(&agg, pub_shares[i]);
        LOGI("Public share initialized for threshold participant %d", i);
    }

    // Generate and accept tuple packets
    int m_len = 0;
    while (message[m_len] != '\0') {
        m_len++;
    }
    LOGI("Message length: %d", m_len);

    tuple_packet* agg_tuple = init_tuple_packet(&agg, message, m_len, threshold_set, threshold);
    for (int i = 0; i < threshold; i++) {
        accept_tuple(&threshold_set[i], agg_tuple);
        LOGI("Participant %d accepted tuple packet", i);
    }

    // Generate signature shares
    LOGI("Generating signature shares");
    for (int i = 0; i < threshold; i++) {
        BIGNUM* sig_share = init_sig_share(&threshold_set[i]);
        accept_sig_share(&agg, sig_share, threshold_set[i].index);
        LOGI("Signature share generated for participant %d", i);
    }

    // Finalize the signature
    signature_packet sig = signature(&agg);
    LOGI("Final signature generated");


    store_signature_and_hash(sig);


    // Clean up dynamically allocated memory
    free(pub_commits);
    free(pub_shares);
    free(threshold_set);
}

void cleanup_participants() {
    if (global_participants != NULL) {
        free(global_participants);
        global_participants = NULL;
        global_participants_count = 0;
    }
}


// Entry point for JNI
void execute_signing(int threshold, int participants, const char* message, int* indices) {
    perform_signing(threshold, participants, message, indices);
}

bool verify_signing(const char* message, int index) {
    if (global_participants == NULL) {
        LOGE("Participants not initialized");
        return false;
    }

    // Validate participant index
    if (index < 0 || index >= global_participants_count) {
        LOGE("Invalid participant index: %d", index);
        return false;
    }

    // Retrieve the participant
    participant* temp_p = &global_participants[index];

    // Verify the signature
    if (!verify_signature(global_signature, global_hash, message, temp_p->public_key)) {
        LOGE("Signature verification failed for participant %d", index);
        return false;
    }
    return true;
}

