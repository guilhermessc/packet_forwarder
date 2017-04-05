#include <stdio.h>

#include <"LoRaMacCrypto.h">

#define com_ADV_HELP		0
#define com_ComputeMic		1
#define com_PayloadEncrypt	2
#define com_PayloadDecrypt	3
#define com_JoinComputeMic	4
#define com_JoinDecrypt		5
#define com_JoinComputeSKeys	6

float stat_ComputeMic		= 0;
float stat_PayloadEncrypt	= 0;
float stat_PayloadDecrypt	= 0;
float stat_JoinComputeMic	= 0;
float stat_JoinDecrypt		= 0;
float stat_JoinComputeSKeys	= 0;

uint16_t pad16_len (uint16_t base) {

	if (base%16)
		return base + 16 - base%16;
	return base;
}

void fComputeMic(){
	uint8_t *buffer;
	uint16_t size;
	uint8_t *key;
	uint32_t address;
	uint8_t dir;
	uint32_t sequenceCounter;
	uint32_t *mic; // caso falhe tentar alocar dinamicamente e reportar para Hélmiton

	scanf("%s %o %s %lo %hho %lo", buffer, &size, key, &address, &dir, &sequenceCounter);
	LoRaMacComputeMic( buffer, size, key, address, dir, sequenceCounter, mic );
	printf("MIC:\t%o.%o.%o.%o\n", mic[0], mic[1], mic[2], mic[3]);
}

void fPayloadEncrypt(){
	uint8_t *buffer;
	uint16_t size, i;
	uint8_t *key;
	uint32_t address;
	uint8_t dir;
	uint32_t sequenceCounter;
	uint8_t *encBuffer; // caso falhe tentar alocar dinamicamente e reportar para Hélmiton

	scanf("%s %o %s %lo %hho %lo", buffer, &size, key, &address, &dir, &sequenceCounter);
	LoRaMacPayloadEncrypt( buffer, size, key, address, dir, sequenceCounter, encBuffer );

	printf("Encrypted buffer:\t");
	for (i=0; i< size; ++i) {
		printf("%o.", encBuffer[i]);
	}
	printf("\n");
}

void fPayloadDecrypt(){
	uint8_t *buffer;
	uint16_t size, i;
	uint8_t *key;
	uint32_t address;
	uint8_t dir;
	uint32_t sequenceCounter;
	uint8_t *decBuffer; // caso falhe tentar alocar dinamicamente e reportar para Hélmiton

	scanf("%s %o %s %lo %hho %lo", buffer, &size, key, &address, &dir, &sequenceCounter);
	LoRaMacPayloadDecrypt( buffer, size, key, address, dir, sequenceCounter, decBuffer );

	printf("Decrypted buffer:\t");
	for (i=0; i< size; ++i) {
		printf("%o.", decBuffer[i]);
	}
	printf("\n");
}

void fJoinComputeMic(){
	uint8_t *buffer;
	uint16_t size;
	uint8_t *key;
	uint32_t *mic;

	scanf("%s %o %s", buffer, &size, key);
	LoRaMacJoinComputeMic( buffer, size, key, mic );
	printf("MIC:\t%o.%o.%o.%o\n", mic[0], mic[1], mic[2], mic[3]);
}

void fJoinDecrypt(){
	uint8_t *buffer;
	uint16_t size, i;
	uint8_t *key;
	uint8_t *decBuffer;

	scanf("%s %o %s", buffer, &size, key);
	LoRaMacJoinDecrypt( buffer, size, key, decBuffer );

	printf("Decrypted buffer:\t");
	for (i=0; i< pad16_len(size); ++i) {
		printf("%o.", decBuffer[i]);
	}
	printf("\n");
}

void fJoinComputeSKeys(){
	uint8_t *key;
	uint8_t *appNonce;
	uint16_t devNonce;
	uint8_t *nwkSKey;
	uint8_t *appSKey;
	uint16_t i;

	scanf("%s %s %o", key, appNonce, devNonce);
	LoRaMacJoinComputeSKeys( key, appNonce, devNonce, nwkSKey, appSKey );

	printf("NwkSKey:\t");
	for (i=0; i<16; ++i) {
		printf("%o.", nwkSKey[i]);
	}
	printf("\n");

	printf("AppSKey:\t");
	for (i=0; i<16; ++i) {
		printf("%o.", appSKey[i]);
	}
	printf("\n");
}

void short_help(){
	pritnf("\n--------------------help--------------------------\n\n                [comand_number][comand_args]\n\nComputeMic\t\t1\nPayloadEncrypt\t2\nPayloadDecrypt\t3\nJoinComputeMic\t4\nJoinDecrypt\t\t5\nJoinComputeSKeys\t6\nADV_HELP\t\t0\n\n\nvoid LoRaMacComputeMic(       const uint8_t *buffer,\n                              uint16_t size,\n                              const uint8_t *key,\n                              uint32_t address,\n                              uint8_t dir,\n                              uint32_t sequenceCounter,\n                              uint32_t *mic );\n\n\nvoid LoRaMacPayloadEncrypt(   const uint8_t *buffer,\n                              uint16_t size,\n                              const uint8_t *key,\n                              uint32_t address,\n                              uint8_t dir,\n                              uint32_t sequenceCounter,\n                              uint8_t *encBuffer );\n\nvoid LoRaMacPayloadDecrypt(   const uint8_t *buffer,\n                              uint16_t size,\n                              const uint8_t *key,\n                              uint32_t address,\n                              uint8_t dir,\n                              uint32_t sequenceCounter,\n                              uint8_t *decBuffer );\n\nvoid LoRaMacJoinComputeMic(   const uint8_t *buffer,\n                              uint16_t size,\n                              const uint8_t *key,\n                              uint32_t *mic );\n\nvoid LoRaMacJoinDecrypt(      const uint8_t *buffer,\n                              uint16_t size,\n                              const uint8_t *key,\n                              uint8_t *decBuffer );\n\nvoid LoRaMacJoinComputeSKeys( const uint8_t *key,\n                              const uint8_t *appNonce,\n                              uint16_t devNonce,\n                              uint8_t *nwkSKey,\n                              uint8_t *appSKey );\n");
}

void test_once(int com){

	switch (com){

	case ComputeMic:
		fComputeMic();
		break;

	case PayloadEncrypt:
		fPayloadEncrypt();
		break;

	case PayloadDecrypt:
		fPayloadDecrypt();
		break;

	case JoinComputeMic:
		fJoinComputeMic();
		break;

	case JoinDecrypt:
		fJoinDecrypt();
		break;

	case JoinComputeSKeys:
		fJoinComputeSKeys();
		break;

	case com_ADV_HELP:
		printf("\n----------------------------------------------------\n\n*!\n * Computes the LoRaMAC frame MIC field\n *\n *  param [IN]  buffer          - Data buffer\n *  param [IN]  size            - Data buffer size\n *  param [IN]  key             - AES key to be used\n *  param [IN]  address         - Frame address\n *  param [IN]  dir             - Frame direction [0: uplink, 1: downlink]\n *  param [IN]  sequenceCounter - Frame sequence counter\n *  param [OUT] mic             - Computed MIC field\n * \nvoid LoRaMacComputeMic( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint32_t address, uint8_t dir, uint32_t sequenceCounter, uint32_t *mic );\n\n *!\n * Computes the LoRaMAC payload encryption\n *\n *  param [IN]  buffer          - Data buffer\n *  param [IN]  size            - Data buffer size\n *  param [IN]  key             - AES key to be used\n *  param [IN]  address         - Frame address\n *  param [IN]  dir             - Frame direction [0: uplink, 1: downlink]\n *  param [IN]  sequenceCounter - Frame sequence counter\n *  param [OUT] encBuffer       - Encrypted buffer\n * \nvoid LoRaMacPayloadEncrypt( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint32_t address, uint8_t dir, uint32_t sequenceCounter, uint8_t *encBuffer );\n\n *!\n * Computes the LoRaMAC payload decryption\n *\n *  param [IN]  buffer          - Data buffer\n *  param [IN]  size            - Data buffer size\n *  param [IN]  key             - AES key to be used\n *  param [IN]  address         - Frame address\n *  param [IN]  dir             - Frame direction [0: uplink, 1: downlink]\n *  param [IN]  sequenceCounter - Frame sequence counter\n *  param [OUT] decBuffer       - Decrypted buffer\n * \nvoid LoRaMacPayloadDecrypt( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint32_t address, uint8_t dir, uint32_t sequenceCounter, uint8_t *decBuffer );\n\n *!\n * Computes the LoRaMAC Join Request frame MIC field\n *\n *  param [IN]  buffer          - Data buffer\n *  param [IN]  size            - Data buffer size\n *  param [IN]  key             - AES key to be used\n *  param [OUT] mic             - Computed MIC field\n * \nvoid LoRaMacJoinComputeMic( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint32_t *mic );\n\n *!\n * Computes the LoRaMAC join frame decryption\n *\n *  param [IN]  buffer          - Data buffer\n *  param [IN]  size            - Data buffer size\n *  param [IN]  key             - AES key to be used\n *  param [OUT] decBuffer       - Decrypted buffer\n * \nvoid LoRaMacJoinDecrypt( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint8_t *decBuffer );\n\n *!\n * Computes the LoRaMAC join frame decryption\n *\n *  param [IN]  buffer          - Data buffer\n *  param [IN]  size            - Data buffer size\n *  param [IN]  key             - AES key to be used\n *  param [OUT] encBuffer       - Encrypted buffer\n * \nvoid LoRaMacJoinEncrypt( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint8_t *encBuffer );\n\n *!\n * Computes the LoRaMAC join frame decryption\n *\n *  param [IN]  key             - AES key to be used\n *  param [IN]  appNonce        - Application nonce\n *  param [IN]  devNonce        - Device nonce\n *  param [OUT] nwkSKey         - Network session key\n *  param [OUT] appSKey         - Application session key\n * \nvoid LoRaMacJoinComputeSKeys( const uint8_t *key, const uint8_t *appNonce, uint16_t devNonce, uint8_t *nwkSKey, uint8_t *appSKey );\n\n");
		break;

	default:
		short_help();
	}
}

int main(){

	int com;

	short_help();
	while(scanf("%d", &com)){
		test_once(com);
	}

	return 0;
}





