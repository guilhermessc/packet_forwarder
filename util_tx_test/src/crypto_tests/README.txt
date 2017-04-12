README

The goal of this directory is to test the modifications at
LoRaMacCrypto.c file.

For more information on what is tested and what is not read
the TODO.txt file.

HOW TO COMPILE test.c:

	At the terminal:

	at path/to/packet_forwarder/util_tx_test/src/ 

	gcc -I /usr/src/openssl-1.0.2k/include/openssl crypto_tests/test.c LoRaMacCrypto.c log_linux.c security.c ecc.c -o lora_crypto -lcrypto
	