#include "../boringssl/include/openssl/bn.h"
#include <stdbool.h>

#include "setup.h"

typedef struct node_pub_share {
  pub_share_packet* rcvd_packets;
  struct node_pub_share* next;
} rcvd_pub_shares;

typedef struct node_sig_share {
  BIGNUM* rcvd_share;
  struct node_sig_share* next;
} rcvd_sig_shares;

typedef struct {
    BIGNUM * signature;
    BIGNUM * hash;
    char* m;
} signature_packet;


typedef struct {
  int threshold;
  BIGNUM* public_key;
  BIGNUM* R_pub_commit;
  BIGNUM* hash;
  tuple_packet* tuple;
  rcvd_pub_shares* rcvd_pub_share_head;
  rcvd_sig_shares* rcvd_sig_shares_head;
} aggregator;

pub_share_packet* init_pub_share(participant* p);

bool accept_pub_share(aggregator* receiver, pub_share_packet* packet);

tuple_packet* init_tuple_packet(aggregator* a, char* m, size_t m_size,
                                participant* set, int set_size);

bool accept_tuple(participant* receiver, tuple_packet* packet);

BIGNUM* init_sig_share(participant* p);

bool accept_sig_share(aggregator* receiver, BIGNUM* sig_share,
                      int sender_index);

signature_packet signature(aggregator* a);

bool verify_signature(char* signature_hex, char* hash_hex, char* m, BIGNUM* Y);