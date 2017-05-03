#bin/bash

rm lora_crypto

gcc -I /usr/src/openssl-1.0.2k/include/openssl \
    crypto_tests/test.c LoRaMacCrypto.c log_linux.c \
    security.c ecc.c -o lora_crypto -lcrypto

./lora_crypto
