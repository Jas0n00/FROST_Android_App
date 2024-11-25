#include "../headers/signing.h"

#include "../boringssl/include/openssl/bn.h"
#include "../boringssl/include/openssl/crypto.h"
#include "../boringssl/include/openssl/rand.h"
#include "../boringssl/include/openssl/ec.h"
#include "../boringssl/include/openssl/obj_mac.h"
#include "../boringssl/include/openssl/sha.h"

#include <stdio.h>
#include <string.h>

#include "../headers/globals.h"
#include "../headers/setup.h"
#include "openssl/digest.h"

/*Preprocess stage*/
pub_share_packet* init_pub_share(participant* p) {
  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* rand = generate_rand();
  p->pub_share = malloc(sizeof(pub_share_packet));
  p->pub_share->pub_share = BN_new();
  p->pub_share->verify_share = BN_new();
  p->pub_share->public_key = BN_new();
  p->nonce = BN_new();
  p->pub_share->sender_index = p->index;

  BN_copy(p->pub_share->verify_share, p->verify_share);
  BN_copy(p->pub_share->public_key, p->public_key);
  BN_copy(p->nonce, rand);
  BN_mul(p->pub_share->pub_share, b_generator, p->nonce, ctx);

  BN_CTX_free(ctx);
  BN_clear_free(rand);

  return p->pub_share;
}

void free_pub_share(pub_share_packet* pub_share) {
  BN_clear_free(pub_share->pub_share);
  BN_clear_free(pub_share->verify_share);
  BN_clear_free(pub_share->public_key);
  free(pub_share);
}

rcvd_pub_shares* create_node_pub_share(pub_share_packet* rcvd_packet) {
  rcvd_pub_shares* newNode = malloc(sizeof(rcvd_pub_shares));
  newNode->rcvd_packets = malloc(sizeof(pub_share_packet));
  newNode->next = NULL;
  newNode->rcvd_packets->verify_share = BN_new();
  newNode->rcvd_packets->pub_share = BN_new();
  newNode->rcvd_packets->public_key = BN_new();

  newNode->rcvd_packets->sender_index = rcvd_packet->sender_index;
  BN_copy(newNode->rcvd_packets->pub_share, rcvd_packet->pub_share);
  BN_copy(newNode->rcvd_packets->verify_share, rcvd_packet->verify_share);
  BN_copy(newNode->rcvd_packets->public_key, rcvd_packet->public_key);

  return newNode;
}

void free_node_pub_share(rcvd_pub_shares* node) {
  if (node == NULL) {
    return;
  }

  free_node_pub_share(node->next);  // free memory for remaining nodes

  if (node->rcvd_packets != NULL) {
    BN_clear_free(node->rcvd_packets->verify_share);
    BN_clear_free(node->rcvd_packets->pub_share);
    BN_clear_free(node->rcvd_packets->public_key);
    node->rcvd_packets->sender_index = 0;
    free(node->rcvd_packets);
  }

  free(node);
}

pub_share_packet* search_node_pub_share(rcvd_pub_shares* head,
                                        int sender_index) {
  rcvd_pub_shares* current = head;  // Initialize current
  while (current != NULL) {
    if (current->rcvd_packets->sender_index == sender_index)
      return current->rcvd_packets;
    current = current->next;
  }
  printf("Sender's public share were not found!");
}

void insert_node_pub_share(aggregator* agg, pub_share_packet* rcvd_packet) {
  rcvd_pub_shares* newNode = create_node_pub_share(rcvd_packet);
  newNode->next = agg->rcvd_pub_share_head;
  agg->rcvd_pub_share_head = newNode;
}

bool accept_pub_share(aggregator* receiver, pub_share_packet* packet) {
  if (receiver->rcvd_pub_share_head == NULL) {
    receiver->rcvd_pub_share_head = create_node_pub_share(packet);
    return true;
  } else {
    insert_node_pub_share(receiver, packet);
    return true;
  }
  return false;
}

bool search_pub_share(rcvd_pub_shares* head, int sender_index) {
  rcvd_pub_shares* current = head;  // Initialize current
  while (current != NULL) {
    if (current->rcvd_packets->sender_index == sender_index) return true;
    current = current->next;
  }
  printf("Sender's public share were not found!");
  return false;
}

void pub_shares_mul(aggregator* a) {
  BIGNUM* res_R_pub_commit = BN_new();
  BN_CTX* ctx = BN_CTX_new();
  a->R_pub_commit = BN_new();
  rcvd_pub_shares* current = a->rcvd_pub_share_head;
  BN_zero(res_R_pub_commit);

  while (current != NULL) {
    BN_CTX_start(ctx);
    BN_mod_add(res_R_pub_commit, res_R_pub_commit,
               current->rcvd_packets->pub_share, order, ctx);
    BN_CTX_end(ctx);
    current = current->next;
  }

  BN_copy(a->R_pub_commit, res_R_pub_commit);

  BN_clear_free(res_R_pub_commit);
  BN_CTX_free(ctx);
}

bool R_pub_commit_compute(aggregator* a, participant* set, int set_size) {
  /*
 # 1. Aggregator computes the signing group’s public commitment ∏ D_ij
 # selected participants P_i broadcast tuple (m, R, S, D_ij ) to every one of
 them.
 #
 */

  bool all_found = true;
  rcvd_pub_shares* currect = a->rcvd_pub_share_head;

  for (int i = 0; i < set_size; i++) {
    if (!search_pub_share(a->rcvd_pub_share_head, set[i].index)) {
      all_found = false;
      break;
    }
  }

  if (all_found) {
    pub_shares_mul(a);
    return true;
  } else {
    printf("Mismatch of signing participant and received shares!");
    return false;
  }
}

tuple_packet* init_tuple_packet(aggregator* a, char* m, size_t m_size,
                                participant* set, int set_size) {
  if (a->threshold != set_size) {
    printf("\nMismatch of threshold and included participants!\n");
    abort();
  }

  if (R_pub_commit_compute(a, set, set_size)) {
    a->tuple = malloc(sizeof(tuple_packet));
    a->tuple->m = malloc(sizeof(char) * m_size);
    a->tuple->S = malloc(sizeof(participant) * set_size);
    a->tuple->R = BN_new();

    a->tuple->m_size = m_size;
    BN_copy(a->tuple->R, a->R_pub_commit);
    a->tuple->S_size = a->threshold;

    for (int i = 0; i < set_size; i++) {
      a->tuple->S[i] = set[i];
    }
    for (int i = 0; i < m_size; i++) {
      a->tuple->m[i] = m[i];
    }
  }

  return a->tuple;
}

void free_tuple_packet(tuple_packet* tuple) {
  if (tuple != NULL) {
    if (tuple->m != NULL) {
      free(tuple->m);
    }
    if (tuple->S != NULL) {
      free(tuple->S);
    }
    if (tuple->R != NULL) {
      BN_free(tuple->R);
    }
    tuple->m_size = 0;
    tuple->S_size = 0;
    free(tuple);
  }
}

bool accept_tuple(participant* receiver, tuple_packet* packet) {
  receiver->rcvd_tuple = malloc(sizeof(tuple_packet));
  receiver->rcvd_tuple->S = malloc(sizeof(participant) * packet->S_size);
  receiver->rcvd_tuple->m = malloc(sizeof(char) * packet->m_size);
  receiver->rcvd_tuple->R = BN_new();

  BN_copy(receiver->rcvd_tuple->R, packet->R);
  receiver->rcvd_tuple->S_size = packet->S_size;
  receiver->rcvd_tuple->m_size = packet->m_size;

  for (int i = 0; i < packet->S_size; i++) {
    receiver->rcvd_tuple->S[i] = packet->S[i];
  }

  for (int i = 0; i < packet->m_size; i++) {
    receiver->rcvd_tuple->m[i] = packet->m[i];
  }

  return true;
}

BIGNUM* lagrange_coefficient(tuple_packet* tuple, int p_index) {
  int num_participants = tuple->S_size;

  // Initialize BIGNUMs
  BN_CTX* ctx = BN_CTX_new();
  BN_CTX* ctx2 = BN_CTX_new();
  BN_CTX* ctx3 = BN_CTX_new();
  BN_CTX* ctx4 = BN_CTX_new();
  BIGNUM* numerator = BN_new();
  BIGNUM* denominator = BN_new();
  BIGNUM* res = BN_new();
  BIGNUM* tmp = BN_new();
  BIGNUM* Q_2 = BN_new();
  BIGNUM* b_2 = BN_new();
  BN_set_word(b_2, 2);

  // Set values for numerator, denominator
  BN_one(numerator);
  BN_one(denominator);

  for (int i = 0; i < num_participants; i++) {
    int index = tuple->S[i].index;
    BIGNUM* b_index = BN_new();
    BIGNUM* b_p_index = BN_new();

    BN_set_word(b_index, index);
    BN_set_word(b_p_index, p_index);
    BN_CTX_start(ctx);

    if (index == p_index) {
      BN_CTX_end(ctx);
      BN_clear_free(b_index);
      BN_clear_free(b_p_index);
      continue;
    }
    BN_mul_word(numerator, index);
    BN_sub(tmp, b_index, b_p_index);
    BN_mul(denominator, denominator, tmp, ctx);

    BN_CTX_end(ctx);
    BN_clear_free(b_index);
    BN_clear_free(b_p_index);
  }

  BN_sub(Q_2, order, b_2);
  BN_mod_exp(tmp, denominator, Q_2, order, ctx2);
  BN_mul(res, numerator, tmp, ctx3);
  BN_mod(res, res, order, ctx4);

  BN_CTX_free(ctx);
  BN_CTX_free(ctx2);
  BN_CTX_free(ctx3);
  BN_CTX_free(ctx4);
  BN_clear_free(numerator);
  BN_clear_free(denominator);
  BN_clear_free(tmp);
  BN_clear_free(Q_2);
  BN_clear_free(b_2);

  return res;
}

BIGNUM* hash_func(BIGNUM* R, char* m) {
  BN_CTX* ctx = BN_CTX_new();
  char* R_hex = BN_bn2dec(R);
  size_t hash_len = strlen(m) + strlen(R_hex);
  char* concat = (char*)malloc(hash_len + 1);

  strcpy(concat, m);
  strcat(concat, R_hex);

  unsigned char hash[SHA256_DIGEST_LENGTH];

  EVP_MD_CTX* mdctx;
  const EVP_MD* md;
  md = EVP_sha256();

  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, concat, hash_len);
  EVP_DigestFinal_ex(mdctx, hash, NULL);
  EVP_MD_CTX_free(mdctx);

  BIGNUM* hash_bn = BN_new();
  BN_bin2bn(hash, SHA256_DIGEST_LENGTH, hash_bn);
  BN_mod(hash_bn, hash_bn, order, ctx);

  BN_CTX_free(ctx);
  OPENSSL_free(R_hex);
  free(concat);

  return hash_bn;
}

BIGNUM* init_sig_share(participant* p) {
  BN_CTX* ctx = BN_CTX_new();
  BN_CTX* ctx2 = BN_CTX_new();
  BN_CTX* ctx3 = BN_CTX_new();
  BN_CTX* ctx4 = BN_CTX_new();
  BIGNUM* sig_share = BN_new();
  BIGNUM* tmp = BN_new();
  BIGNUM* lambda = lagrange_coefficient(p->rcvd_tuple, p->index);
  BN_one(tmp);

  BIGNUM* hash = hash_func(p->rcvd_tuple->R, p->rcvd_tuple->m);

  BN_mod_mul(tmp, tmp, hash, order, ctx);
  BN_mod_mul(tmp, tmp, p->secret_share, order, ctx2);
  BN_mod_mul(tmp, tmp, lambda, order, ctx3);
  BN_mod_add(sig_share, p->nonce, tmp, order, ctx4);

  BN_CTX_free(ctx);
  BN_CTX_free(ctx2);
  BN_CTX_free(ctx3);
  BN_CTX_free(ctx4);
  BN_clear_free(hash);
  BN_clear_free(lambda);
  BN_clear_free(tmp);
  BN_clear_free(p->nonce);
  free_pub_share(p->pub_share);
  free_tuple_packet(p->rcvd_tuple);

  return sig_share;
}

rcvd_sig_shares* create_node_sig_share(BIGNUM* sig_share) {
  rcvd_sig_shares* newNode = (rcvd_sig_shares*)malloc(sizeof(rcvd_sig_shares));
  newNode->rcvd_share = BN_new();
  newNode->next = NULL;

  BN_copy(newNode->rcvd_share, sig_share);

  return newNode;
}

void free_rcvd_sig_share(rcvd_sig_shares* node) {
  rcvd_sig_shares* curr = node;
  while (curr != NULL) {
    rcvd_sig_shares* next = curr->next;
    BN_clear_free(curr->rcvd_share);
    free(curr);
    curr = next;
  }
}

void insert_node_sig_share(aggregator* agg, BIGNUM* sig_share) {
  rcvd_sig_shares* newNode = create_node_sig_share(sig_share);

  newNode->next = agg->rcvd_sig_shares_head;
  agg->rcvd_sig_shares_head = newNode;
}

bool accept_sig_share(aggregator* receiver, BIGNUM* sig_share,
                      int sender_index) {
  if (receiver->rcvd_sig_shares_head == NULL) {
    receiver->rcvd_sig_shares_head = create_node_sig_share(sig_share);
  } else {
    insert_node_sig_share(receiver, sig_share);
  }

  /*
  # Verifies the validity of each response by checking
  zi ?= Di * Yi ^ (c * λi)
  */

  pub_share_packet* sender_pub_share =
      search_node_pub_share(receiver->rcvd_pub_share_head, sender_index);

  BN_CTX* ctx = BN_CTX_new();
  BN_CTX* ctx2 = BN_CTX_new();
  BN_CTX* ctx3 = BN_CTX_new();
  BN_CTX* ctx4 = BN_CTX_new();
  BIGNUM* res_G_over_zi = BN_new();
  receiver->hash = BN_new();
  BIGNUM* tmp = BN_new();
  BIGNUM* Yi = BN_new();
  BIGNUM* Di = BN_new();
  BIGNUM* c = hash_func(receiver->R_pub_commit, receiver->tuple->m);
  BIGNUM* res_power = BN_new();
  receiver->public_key = BN_new();
  BIGNUM* lambda;
  BN_copy(Yi, sender_pub_share->verify_share);
  BN_copy(Di, sender_pub_share->pub_share);
  BN_copy(receiver->hash, c);
  BN_copy(receiver->public_key,
          receiver->rcvd_pub_share_head->rcvd_packets->public_key);

  for (int i = 0; i < receiver->tuple->S_size; i++) {
    if (receiver->tuple->S[i].index == sender_index) {
      lambda = lagrange_coefficient(receiver->tuple, sender_index);
    }
  }

  BN_mod_mul(res_G_over_zi, b_generator, sig_share, order, ctx);

  BN_mod_mul(res_power, c, lambda, order, ctx2);
  BN_mod_mul(tmp, Yi, res_power, order, ctx3);
  BN_mod_add(tmp, tmp, Di, order, ctx4);

  if (!BN_cmp(res_G_over_zi, tmp)) {
    BN_CTX_free(ctx);
    BN_CTX_free(ctx2);
    BN_CTX_free(ctx3);
    BN_CTX_free(ctx4);
    BN_clear_free(sig_share);
    BN_clear_free(res_G_over_zi);
    BN_clear_free(tmp);
    BN_clear_free(Yi);
    BN_clear_free(Di);
    BN_clear_free(c);
    BN_clear_free(lambda);
    BN_clear_free(res_power);

    return true;
  } else {
    printf("\nVerification of signing response failed!\n");
    abort();
  }
}

BIGNUM* gen_signature(rcvd_sig_shares* head) {
  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* sum = BN_new();
  BN_zero(sum);

  while (head != NULL) {
    BN_CTX_start(ctx);
    BN_mod_add(sum, sum, head->rcvd_share, order, ctx);
    BN_CTX_end(ctx);
    head = head->next;
  }

  BN_CTX_free(ctx);
  return sum;
}

signature_packet signature(aggregator* agg) {
    /*
    # 1. Compute the group’s response z = ∑ z_i
    # 2. Publish the signature σ = (z, c) along with the message m
    */
    BIGNUM* signature = gen_signature(agg->rcvd_sig_shares_head);

    signature_packet sig_packet;
    sig_packet.hash = BN_new();
    sig_packet.signature = BN_new();

    // Copy BIGNUM values to the signature_packet
    BN_copy(sig_packet.signature, signature);
    BN_copy(sig_packet.hash, agg->hash);


    // Cleanup BIGNUM objects
    BN_clear_free(signature);
    BN_clear_free(agg->R_pub_commit);
    BN_clear_free(agg->hash);
    free_node_pub_share(agg->rcvd_pub_share_head);
    free_tuple_packet(agg->tuple);
    free_rcvd_sig_share(agg->rcvd_sig_shares_head);

    return sig_packet;
}

BIGNUM* hex_string_to_bn(const char* hex_str) {
    if (hex_str == NULL) {
        return NULL; // Invalid input
    }

    BIGNUM* bn = BN_new();
    if (BN_hex2bn(&bn, hex_str) == 0) {
        // Conversion failed, return NULL
        return NULL;
    }

    return bn;
}

bool verify_signature(char* signature_hex, char* hash_hex, char* m, BIGNUM* Y) {
  BIGNUM* R0 = BN_new();
  BIGNUM* z0 = BN_new();
  BIGNUM* temp1 = BN_new();
  BIGNUM* temp2 = BN_new();
  BIGNUM* temp3 = BN_new();
  BN_CTX* ctx = BN_CTX_new();
  BN_CTX* ctx2 = BN_CTX_new();
  BN_CTX* ctx3 = BN_CTX_new();

  BIGNUM* signature = hex_string_to_bn(signature_hex);
  BIGNUM* hash = hex_string_to_bn(hash_hex);

  // Compute R0 = g^z * Y^-c mod order
  BN_mod_mul(temp1, b_generator, signature, order, ctx);
  BN_mod_mul(temp3, Y, hash, order, ctx2);
  BN_mod_sub(R0, temp1, temp3, order, ctx3);

  z0 = hash_func(R0, m);

  if (!BN_cmp(hash, z0)) {
    BN_clear_free(R0);
    BN_clear_free(z0);
    BN_clear_free(temp1);
    BN_clear_free(temp2);
    BN_clear_free(temp3);
    BN_clear_free(signature);
    BN_clear_free  (hash);
    BN_CTX_free(ctx);
    BN_CTX_free(ctx2);
    BN_CTX_free(ctx3);
    //free_curve(); //disabled for test app; otherwise mandatory to enable the cleaning

    printf("\nSignature is verified!\n");
    return true;
  } else {
    printf("\nVerification of signature failed!\n");
    return false;
  }
}
