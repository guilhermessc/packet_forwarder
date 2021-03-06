#include <stdio.h>
#include <stdlib.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#define secp128r1	16
#define secp192r1	24
#define secp256r1	32
#define secp384r1	48
#define ECC_CURVE	secp256r1

#if (ECC_CURVE != secp192r1 && ECC_CURVE != secp256r1 \
	&& ECC_CURVE != secp384r1)
	#error "ERROR_CURVE_NOT_DEFINED"
#endif

#define NUM_ECC_DIGITS ECC_CURVE

int encrypt(uint8_t *plaintext, size_t plaintext_len,
			uint8_t *key, uint8_t *iv);
int decrypt(uint8_t *ciphertext, size_t ciphertext_len,
			uint8_t *key, uint8_t *iv);
int encrypt_lora(uint8_t *plaintext, size_t plaintext_len,
			uint8_t *key, uint8_t *iv);
int decrypt_lora(uint8_t *ciphertext, size_t ciphertext_len,
			uint8_t *key, uint8_t *iv);
int derive_secret(uint8_t stpx[],uint8_t stpy[], uint8_t lcpriv[],
			uint8_t lcpx[], uint8_t lcpy[], uint8_t secret[], uint8_t *iv);
int generate_keys(uint8_t *keys);
int lora_cmac(uint8_t *plaintext, size_t plaintext_len, uint8_t *mact,
 						size_t mact_len, uint8_t *key, unsigned char *iv);
