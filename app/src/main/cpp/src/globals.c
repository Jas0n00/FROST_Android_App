#include "../headers/globals.h"

#include "../boringssl/include/openssl/bn.h"
#include "../boringssl/include/openssl/ec.h"
#include "../boringssl/include/openssl/obj_mac.h"
#include "openssl/rand.h"
#include "openssl/mem.h"
#include <stdio.h>

void initialize_curve_parameters() {
  ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  if (!ec_group) {
    printf("Error creating EC group\n");
    return;
  }

  p_generator = EC_GROUP_get0_generator(ec_group);

  // serialize the point into a byte array; The EC_POINT_point2bn has been
  // deprecated since OpenSSL 3.0
  size_t buf_len = EC_POINT_point2oct(
      ec_group, p_generator, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
  unsigned char* buf = OPENSSL_malloc(buf_len);
  EC_POINT_point2oct(ec_group, p_generator, POINT_CONVERSION_UNCOMPRESSED, buf,
                     buf_len, NULL);

  // create a BIGNUM from the byte array
  b_generator = BN_bin2bn(buf, buf_len, NULL);
  if (!b_generator) {
    printf("Error creating BIGNUM from byte array\n");
    return;
  }

  order = EC_GROUP_get0_order(ec_group);

  // free the memory allocated for buf
  OPENSSL_free(buf);
}

void free_curve() {
  if (ec_group) {
    EC_GROUP_free(ec_group);
    ec_group = NULL;
  }

  if (b_generator) {
    BN_free(b_generator);
    b_generator = NULL;
  }
}

BIGNUM* generate_rand() {
  BIGNUM* rand_num;
  unsigned char buffer[NUM_BYTES];

  // generate random bytes
  if (RAND_bytes(buffer, NUM_BYTES) != 1) {
    printf("Error generating random bytes\n");
    exit(EXIT_FAILURE);
  }

  // convert buffer to a bignum
  rand_num = BN_bin2bn(buffer, NUM_BYTES, NULL);

  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* result = BN_new();
  BN_mod(result, rand_num, order, ctx);

  OPENSSL_cleanse(buffer,
                  sizeof(buffer));  // free the memory allocated for buffer
  BN_CTX_free(ctx);
  BN_clear_free(rand_num);
  return result;
}

