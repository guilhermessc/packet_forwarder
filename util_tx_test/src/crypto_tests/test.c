#include <stdio.h>
#include <stdint.h>

#include "../../inc/LoRaMacCrypto.h"

#define com_ADV_HELP			0
#define com_ComputeMic			1
#define com_PayloadEncrypt		2
#define com_PayloadDecrypt		3
#define com_JoinComputeMic		4
#define com_JoinDecrypt			5
#define com_JoinEncrypt			6
#define com_JoinComputeSKeys	7

// float stat_ComputeMic		= 0;
// float stat_PayloadEncrypt	= 0;
// float stat_PayloadDecrypt	= 0;
// float stat_JoinComputeMic	= 0;
// float stat_JoinDecrypt		= 0;
// float stat_JoinComputeSKeys	= 0;

uint8_t Key[16] = {	0x30, 0x31, 0x31, 0x31, 0x31, 0x31, \
					0x31, 0x31, 0x31, 0x31, 0x31, 0x31, \
					0x31, 0x31, 0x31, 0x31 }; 
uint8_t Buffer[16] = {	0x30, 0x31, 0x31, 0x31, 0x31, 0x31, \
						0x31, 0x31, 0x31, 0x31, 0x31, 0x31, \
						0x31, 0x31, 0x31, 0x31 }; 
uint16_t SizeB = (uint16_t) (sizeof(Buffer)/sizeof(uint8_t));
uint32_t Address = 32;
uint8_t Dir = 1;
uint32_t SequenceCounter = 2;
uint32_t Mic[4];
uint8_t tmpBuffer[100];
uint8_t joinAcceptCore[12] = {	0x0a, 0x0a, 0x0a, 0x0b, \
								0x0b, 0x0b, 0x0d, 0x0d, \
								0x0d, 0x0d, 0x01, 0x02, }; // join accept w/o MIC
uint16_t SizeJ = (uint16_t) (sizeof(joinAcceptCore)/sizeof(uint8_t));

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
	uint32_t *mic;

	buffer = Buffer;
	size = SizeB;
	key = Key;
	address = Address;
	dir = Dir;
	sequenceCounter = SequenceCounter;
	mic = Mic;

	LoRaMacComputeMic( buffer, size, key, address, dir, sequenceCounter, mic );
	printf("MIC:\t");
	print_hex(mic, 4);
}

void fPayloadEncrypt(){
	uint8_t *buffer;
	uint16_t size, i;
	uint8_t* key;
	uint32_t address;
	uint8_t dir;
	uint32_t sequenceCounter;
	uint8_t *encBuffer;

	buffer = Buffer;
	size = SizeB;
	key = Key;
	address = Address;
	dir = Dir;
	sequenceCounter = SequenceCounter;
	encBuffer = tmpBuffer;

	LoRaMacPayloadEncrypt( buffer, size, key, address, dir, sequenceCounter, encBuffer );

	printf("Encrypted buffer:\t");
	print_hex(encBuffer, size);
}

void fPayloadDecrypt(){
	uint8_t *buffer;
	uint16_t size;
	uint8_t *key;
	uint32_t address;
	uint8_t dir;
	uint32_t sequenceCounter;
	uint8_t *decBuffer;

	buffer = Buffer;
	size = SizeB;
	key = Key;
	address = Address;
	dir = Dir;
	sequenceCounter = SequenceCounter;
	decBuffer = tmpBuffer;	

	LoRaMacPayloadDecrypt( buffer, size, key, address, dir, sequenceCounter, decBuffer );

	printf("Decrypted buffer:\t");
	print_hex(decBuffer, size);
}

void fJoinComputeMic(){
	uint8_t *buffer;
	uint16_t size;
	uint8_t *key;
	uint32_t *mic;

	buffer = joinAcceptCore;
	size = SizeJ;
	key = Key;
	mic = Mic;

	LoRaMacJoinComputeMic( buffer, size, key, mic );
	printf("MIC:\t");
	print_hex(mic, 4);
}

void fJoinDecrypt(){
	uint8_t *buffer;
	uint16_t size, i;
	uint8_t *key;
	uint8_t *decBuffer;

	buffer = joinAcceptCore;
	size = SizeJ;
	key = Key;
	decBuffer = tmpBuffer;

	LoRaMacJoinDecrypt( buffer, size, key, decBuffer );

	printf("Decrypted buffer:\t");
	print_hex(decBuffer, pad16_len(size));
}

void fJoinEncrypt(){
	uint8_t *buffer;
	uint16_t size, i;
	uint8_t *key;
	uint8_t *encBuffer;

	buffer = joinAcceptCore;
	size = SizeJ;
	key = Key;
	encBuffer = tmpBuffer;

	LoRaMacJoinEncrypt( buffer, size, key, encBuffer );

	printf("Encrypted buffer:\t");
	print_hex(encBuffer, pad16_len(size));	
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
	printf("\n--------------------help--------------------------\n\n                [comand_number][comand_args]\n\nComputeMic\t\t1\nPayloadEncrypt\t\t2\nPayloadDecrypt\t\t3\nJoinComputeMic\t\t4\nJoinDecrypt\t\t5\nJoinComputeSKeys\t6\nADV_HELP\t\t0\n\n\nvoid LoRaMacComputeMic(       const uint8_t *buffer,\n                              uint16_t size,\n                              const uint8_t *key,\n                              uint32_t address,\n                              uint8_t dir,\n                              uint32_t sequenceCounter,\n                              uint32_t *mic );\n\n\nvoid LoRaMacPayloadEncrypt(   const uint8_t *buffer,\n                              uint16_t size,\n                              const uint8_t *key,\n                              uint32_t address,\n                              uint8_t dir,\n                              uint32_t sequenceCounter,\n                              uint8_t *encBuffer );\n\nvoid LoRaMacPayloadDecrypt(   const uint8_t *buffer,\n                              uint16_t size,\n                              const uint8_t *key,\n                              uint32_t address,\n                              uint8_t dir,\n                              uint32_t sequenceCounter,\n                              uint8_t *decBuffer );\n\nvoid LoRaMacJoinComputeMic(   const uint8_t *buffer,\n                              uint16_t size,\n                              const uint8_t *key,\n                              uint32_t *mic );\n\nvoid LoRaMacJoinDecrypt(      const uint8_t *buffer,\n                              uint16_t size,\n                              const uint8_t *key,\n                              uint8_t *decBuffer );\n\nvoid LoRaMacJoinComputeSKeys( const uint8_t *key,\n                              const uint8_t *appNonce,\n                              uint16_t devNonce,\n                              uint8_t *nwkSKey,\n                              uint8_t *appSKey );\n");
}

void test_once(int com){

	switch (com){

	case com_ComputeMic:
		fComputeMic();
		break;

	case com_PayloadEncrypt:
		fPayloadEncrypt();
		break;

	case com_PayloadDecrypt:
		fPayloadDecrypt();
		break;

	case com_JoinComputeMic:
		fJoinComputeMic();
		break;

	case com_JoinDecrypt:
		fJoinDecrypt();
		break;

	case com_JoinEncrypt:
		fJoinEncrypt();
		break;

	case com_JoinComputeSKeys:
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
		fJoinEncrypt();
		// test_once(com);
	}

	return 0;
}





