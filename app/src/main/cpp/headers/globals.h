#include "../boringssl/include/openssl/bn.h"
#include "../boringssl/include/openssl/ec.h"
#include "setup.h"


extern EC_GROUP* ec_group;
extern const EC_POINT* p_generator;
extern const BIGNUM* b_generator;
extern const BIGNUM* order;
extern char* global_signature;
extern char* global_hash;
extern participant* global_participants;
extern int global_participants_count;
#define NUM_BYTES 32

void initialize_curve_parameters();

void free_curve();

BIGNUM* generate_rand();