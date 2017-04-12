HOW TO COMPILE LoraMacCrypto.c:

1 - add in LoraMacCrypto.c:
	int main(){ return 0;}

2 - At the terminal:
	gcc -I /usr/src/openssl-1.0.2k/include/openssl LoRaMacCrypto.c log_linux.c security.c ecc.c -o lora_crypto -lcrypto
