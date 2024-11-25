#ifndef PARTICIPANT_ATRIBUTES
#define PARTICIPANT_ATRIBUTES

#include "../boringssl/include/openssl/bn.h"
#include <stdbool.h>

typedef struct participant participant;  // Forward declaration

typedef struct {
  size_t coefficient_list_len;
  BIGNUM** coeff;
} coeff_list;

typedef struct {
  int sender_index;
  size_t commit_len;
  BIGNUM** commit;
} pub_commit_packet;

typedef struct {
  int sender_index;
  BIGNUM* verify_share;
  BIGNUM* pub_share;
  BIGNUM* public_key;
} pub_share_packet;

typedef struct {
  BIGNUM* coefficient;
  BIGNUM* exponent;
} term;

typedef struct {
  int n;
  term* t;
} poly;

typedef struct node_commit {
  struct node_commit* next;
  pub_commit_packet* rcvd_packet;
} rcvd_pub_commits;

typedef struct node_share {
  struct node_share* next;
  BIGNUM* rcvd_share;
} rcvd_sec_shares;

typedef struct {
  char* m;
  size_t m_size;
  BIGNUM* R;
  participant* S;
  size_t S_size;
} tuple_packet;

struct participant {
  int index;
  int threshold;
  int participants;
  BIGNUM* secret_share;
  BIGNUM* verify_share;
  BIGNUM* public_key;
  BIGNUM* nonce;
  coeff_list* list;
  pub_commit_packet* pub_commit;
  poly* func;
  rcvd_pub_commits* rcvd_commit_head;
  rcvd_sec_shares* rcvd_sec_share_head;
  pub_share_packet* pub_share;
  tuple_packet* rcvd_tuple;
};

/*Pedersen Distributed Key Generation*/

pub_commit_packet* init_pub_commit(participant* p);

void free_pub_commit(pub_commit_packet* pub_commit);

bool accept_pub_commit(participant* reciever, pub_commit_packet* pub_commit);

BIGNUM* init_sec_share(participant* sender, int reciever_index);

bool accept_sec_share(participant* reciever, int sender_index,
                      BIGNUM* sec_share);

void gen_keys(participant* p);

#endif