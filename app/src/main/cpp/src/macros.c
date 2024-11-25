#include "../boringssl/include/openssl/bn.h"
#include "../boringssl/include/openssl/ec.h"
#include "setup.h"

BIGNUM* order;
BIGNUM* b_generator;
EC_POINT* p_generator;
EC_GROUP* ec_group;
char* global_signature;
char* global_hash;
participant* global_participants;
int global_participants_count;