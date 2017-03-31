/*
 / _____)             _              | |
( (____  _____ ____ _| |_ _____  ____| |__
 \____ \| ___ |    (_   _) ___ |/ ___)  _ \
 _____) ) ____| | | || |_| ____( (___| | | |
(______/|_____)_|_|_| \__)_____)\____)_| |_|
  (C)2013 Semtech-Cycleo

Description:
    Ask a gateway to emit packets using GW <-> server protocol

License: Revised BSD License, see LICENSE.TXT file include in the project
Maintainer: Sylvain Miermont
*/


/* -------------------------------------------------------------------------- */
/* --- DEPENDANCIES --------------------------------------------------------- */

/* fix an issue between POSIX and C99 */
#if __STDC_VERSION__ >= 199901L
    #define _XOPEN_SOURCE 600
#else
    #define _XOPEN_SOURCE 500
#endif

#include <stdint.h>     /* C99 types */
#include <stdbool.h>    /* bool type */
#include <stdio.h>      /* printf fprintf sprintf fopen fputs */
#include <unistd.h>     /* getopt access usleep */

#include <string.h>     /* memset */
#include <signal.h>     /* sigaction */
#include <stdlib.h>     /* exit codes */
#include <errno.h>      /* error messages */

#include <sys/socket.h> /* socket specific definitions */
#include <netinet/in.h> /* INET constants and stuff */
#include <arpa/inet.h>  /* IP address conversion stuff */
#include <netdb.h>      /* gai_strerror */

#include "parson.h"
#include "base64.h"
#include "aes.h"
#include "cmac.h"
/* -------------------------------------------------------------------------- */
/* --- PRIVATE MACROS ------------------------------------------------------- */

#define ARRAY_SIZE(a)   (sizeof(a) / sizeof((a)[0]))
#define MSG(args...)    fprintf(stdout, args) /* message that is destined to the user */

/* -------------------------------------------------------------------------- */
/* --- PRIVATE CONSTANTS ---------------------------------------------------- */

#define PROTOCOL_VERSION 2

#define PKT_PUSH_DATA   0
#define PKT_PUSH_ACK    1
#define PKT_PULL_DATA   2
#define PKT_PULL_RESP   3
#define PKT_PULL_ACK    4
#define PKT_TX_ACK		5

#define JOIN_ACCEPT		0x20
#define JOIN_REQUEST	0x00


/* -------------------------------------------------------------------------- */
/* --- PRIVATE VARIABLES (GLOBAL) ------------------------------------------- */

/* signal handling variables */
struct sigaction sigact; /* SIGQUIT&SIGINT&SIGTERM signal handling */
static int exit_sig = 0; /* 1 -> application terminates cleanly (shut down hardware, close open files, etc) */
static int quit_sig = 0; /* 1 -> application terminates without shutting down the hardware */

int count = 0;

/* -------------------------------------------------------------------------- */
/* --- PRIVATE FUNCTIONS DECLARATION ---------------------------------------- */

static void sig_handler(int sigio);

void usage (void);

/* -------------------------------------------------------------------------- */
/* --- PRIVATE FUNCTIONS DEFINITION ----------------------------------------- */

static void sig_handler(int sigio) {
    if (sigio == SIGQUIT) {
        quit_sig = 1;;
    } else if ((sigio == SIGINT) || (sigio == SIGTERM)) {
        exit_sig = 1;
    }
}

/* parser devices.json - registrar thing no gw */
void save_thing(const char *file, uint8_t *payload_rx) {

	JSON_Value *root_value_keys, *value_new;
	JSON_Object *root_obj_keys, *obj_new;
	JSON_Array *array_keys_key;
	printf("DEBUG 3");
	root_value_keys = json_parse_file(file);
	root_obj_keys = json_value_get_object(root_value_keys);
	array_keys_key = json_object_get_array(root_obj_keys, "keys");

	//montando o novo objeto que vai no array
	value_new = json_value_init_object();
	obj_new = json_value_get_object(value_new);
	json_object_set_number(obj_new, "devaddr", count);
	json_object_set_string(obj_new, "payload", ((char *)payload_rx));
	count++;
	//adicionando no array o objeto
	json_array_append_value(array_keys_key, value_new);

	//colocando no arquivo
	printf("ESCREVENDO NO ARQUIVO JSON!!!!!!!!!!!!!!!!");
	json_serialize_to_file_pretty(root_value_keys, file); //mudar para sem pretty depois

	json_object_clear(obj_new);
	json_array_clear(array_keys_key);
	json_object_clear(root_obj_keys);
	json_value_free(root_value_keys);
	
}

void parser_data(uint8_t *databuf, uint8_t *payload_rx, uint32_t *tmst_rx, size_t *size, int *rssi_rx) {
	
	JSON_Value *root_value_pd, *value_tmp;
	JSON_Object *root_obj_pd, *obj_array;
	JSON_Array *array_pd_rxpk;
	size_t icount;
	char payload_rx_b64[341];				// documentar de onde veio esse valor (usar um define talvez)
	
	root_value_pd = json_parse_string((char *)&databuf[12]);
	root_obj_pd = json_value_get_object(root_value_pd);
	array_pd_rxpk = json_object_get_array  (root_obj_pd, "rxpk");
		printf("DEBUG 1");
	icount = json_array_get_count(array_pd_rxpk);
	for(size_t i=0; i<icount; ++i) {
		obj_array = json_array_get_object (array_pd_rxpk, i);
		
		value_tmp = json_object_get_value(obj_array, "tmst");
		*tmst_rx = ((uint32_t)json_value_get_number(value_tmp));
		
		value_tmp = json_object_get_value(obj_array, "size");
		*size = ((size_t)json_value_get_number(value_tmp));
		printf("SIZE: %u\n", *size);

		value_tmp = json_object_get_value(obj_array, "data");
		strcpy(payload_rx_b64, json_value_get_string (value_tmp));
		b64_to_bin(payload_rx_b64, *size, payload_rx, 255);
		
		value_tmp = json_object_get_value(obj_array, "rssi");
		*rssi_rx = ((int)json_value_get_number(value_tmp));
		
		json_object_clear(obj_array);
	}
	printf("DEBUG 2");
	json_array_clear(array_pd_rxpk);
	json_object_clear(root_obj_pd);
	json_value_free(root_value_pd);
	
}

/* -------------------------------------------------------------------------- */
/* --- MAIN FUNCTION -------------------------------------------------------- */

int main()
{
    int i, x;
    const char file[] = "devices.json";
    
    /* network and aplication keys and join parameters */
 
	const uint8_t netID[3] 	= {0x30, 0x01, 0x01};
	const uint8_t appKey[16]= {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 
									0xCF, 0x4F, 0x3C}; 
/*  
	uint8_t devAddr[4];
    uint8_t appNonce[3];
    
    uint8_t dlSettings 	= 0x00;
    uint8_t rxDelay		= 0x00;
*/
    /* application parameters */
    char mod[64] 		= "LORA"; 	/* LoRa modulation by default */
    float f_target 		= 923.3; 	/* target frequency */
    int sf 				= 10; 		/* SF12 by default */
    int bw 				= 125; 		/* 500kHz bandwidth by default */
    int pow 			= 14; 		/* 14 dBm by default */
    int delay 			= 1; 		/* 1 milisecond between packets by default */
    int repeat 			= 1; 		/* sweep only once by default */
    bool invert 		= true;
    float br_kbps 		= 50; 		/* 50 kbps by default */
    uint8_t fdev_khz 	= 25; 		/* 25 khz by default */
    
    /* rx packet variables */
	uint32_t tmst_rx 	= 0;		/* rxpk timestamp */
	uint32_t delay_dw2 = 6000000;  /* delay for the second window */ 
	size_t size_rx		= 0;		/* rx payload size */
	uint8_t payl_rx[255];
	int rssi_rx;

    /* packet payload variables */
    int payload_size 	= 17;
    uint8_t payload_bin[255];
    char payload_b64[341];
    int payload_index;
    uint8_t payload_bin_dec[255]; 	/* crypto payload */
    
    /* AES and CMAC variables */
    static aes_context AesContext;
	static AES_CMAC_CTX AesCmacCtx[1];
	static uint8_t Mic[16];

    /* server socket creation */
    int sock; 						/* socket file descriptor */
    struct addrinfo hints;
    struct addrinfo *result; 		/* store result of getaddrinfo */
    struct addrinfo *q; 			/* pointer to move into *result data */
    char serv_port[8] 	= "1680";
    char host_name[64];
    char port_name[64];

    /* variables for receiving and sending packets */
    struct sockaddr_storage dist_addr;
    socklen_t addr_len 	= sizeof dist_addr;
    uint8_t databuf[500];
    int buff_index;
    int byte_nb;

    /* variables for gateway identification */
    uint32_t raw_mac_h; 			/* Most Significant Nibble, network order */
    uint32_t raw_mac_l; 			/* Least Significant Nibble, network order */
    uint64_t gw_mac; 				/* MAC address of the client (gateway) */
    uint8_t ack_command, bok_push_data;

    /* prepare hints to open network sockets */
    memset(&hints, 0, sizeof hints);
    hints.ai_family 	= AF_UNSPEC; 	/* should handle IP v4 or v6 automatically */
    hints.ai_socktype 	= SOCK_DGRAM;
    hints.ai_flags 		= AI_PASSIVE; 	/* will assign local IP automatically */


    /* compose local address (auto-complete a structure for socket) */
    i = getaddrinfo(NULL, serv_port, &hints, &result);
    if (i != 0) {
        MSG("ERROR: getaddrinfo returned %s\n", gai_strerror(i));
        exit(EXIT_FAILURE);
    }

    /* try to open socket and bind to it */
    for (q=result; q!=NULL; q=q->ai_next) {
        sock = socket(q->ai_family, q->ai_socktype,q->ai_protocol);
        if (sock == -1) {
            continue; 				/* socket failed, try next field */
        } else {
            i = bind(sock, q->ai_addr, q->ai_addrlen);
            if (i == -1) {
                shutdown(sock, SHUT_RDWR);
                continue; 			/* bind failed, try next field */
            } else {
                break; 				/* success, get out of loop */
            }
        }
    }
    if (q == NULL) {
        MSG("ERROR: failed to open socket or to bind to it\n");
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(result);

    /* configure signal handling */
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags 	= 0;
    sigact.sa_handler 	= sig_handler;
    sigaction(SIGQUIT, &sigact, NULL);
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);

    /* display setup summary */
    if (strcmp(mod, "FSK") == 0) {
        MSG("INFO: %i FSK pkts @%f MHz (FDev %u kHz, Bitrate %.2f kbps, %uB payload) %i dBm, %i ms between each\n", repeat, f_target, fdev_khz, br_kbps, payload_size, pow, delay);
    } else {
        MSG("INFO: %i LoRa pkts @%f MHz (BW %u kHz, SF%i, %uB payload) %i dBm, %i ms between each\n", repeat, f_target, bw, sf, payload_size, pow, delay);
    }
    
    bok_push_data = false;

    
    while (1){
	/* wait to receive a request packet */
	MSG("INFO: waiting to receive a request on port %s\n", serv_port);
        byte_nb = recvfrom(sock, databuf, sizeof databuf, 0, (struct sockaddr *)&dist_addr, &addr_len);
	/* exit loop on user signals */
	if ((quit_sig == 1) || (exit_sig == 1))
		break;

        if (byte_nb < 0) {
            MSG("WARNING: recvfrom returned %s \n", strerror(errno));
            continue;
        }

        /* display info about the sender */
        i = getnameinfo((struct sockaddr *)&dist_addr, addr_len, host_name, sizeof host_name, port_name, sizeof port_name, NI_NUMERICHOST);
        if (i == -1) {
            MSG("WARNING: getnameinfo returned %s \n", gai_strerror(i));
            continue;
        }
        printf(" -> PKT IN: host %s (port %s), %i bytes", host_name, port_name, byte_nb);

        /* check and parse the payload */
        if (byte_nb < 12) { /* not enough bytes for packet from gateway */
            printf(" (too short for GW <-> MAC protocol)\n");
            continue;
        }
        /* don't touch the token in position 1-2, it will be sent back "as is" for acknowledgement */
        if (databuf[0] != PROTOCOL_VERSION) { /* check protocol version number */
            printf(", invalid version %u\n", databuf[0]);
            continue;
        }

		/* retrieve gateway MAC from the request */
        raw_mac_h = *((uint32_t *)(databuf+4));
        raw_mac_l = *((uint32_t *)(databuf+8));
        gw_mac = ((uint64_t)ntohl(raw_mac_h) << 32) + (uint64_t)ntohl(raw_mac_l);

        /* interpret gateway command */
        switch (databuf[3]) {
            case PKT_PUSH_DATA:
                printf(", PUSH_DATA from gateway 0x%08X%08X\n", (uint32_t)(gw_mac >> 32), (uint32_t)(gw_mac & 0xFFFFFFFF));
                ack_command = PKT_PUSH_ACK;
                printf("<-  pkt out, PUSH_ACK for host %s (port %s)", host_name, port_name);
                break;
            case PKT_PULL_DATA:
                printf(", PULL_DATA from gateway 0x%08X%08X\n", (uint32_t)(gw_mac >> 32), (uint32_t)(gw_mac & 0xFFFFFFFF));
                ack_command = PKT_PULL_ACK;
                printf("<-  pkt out, PULL_ACK for host %s (port %s)", host_name, port_name);
                bok_push_data = true;
                break;
            case PKT_TX_ACK:
		databuf[byte_nb] = 0;
                printf("\n    TX_ACK received: '%s'\n", &databuf[12]);
                continue;
            default:
                printf(", unexpected command %u\n", databuf[3]);
                continue;
        }

        /* add some artificial latency */
        //usleep(30000); /* 30 ms */

        /* send acknowledge and check return value */
        databuf[3] = ack_command;
        byte_nb = sendto(sock, (void*)databuf, 4, 0, (struct sockaddr *)&dist_addr, addr_len);
        if (byte_nb == -1) {
            printf(", send error:%s\n", strerror(errno));
        } else {
            printf(", %s sent %i bytes sent\n", ack_command == PKT_PUSH_ACK ? "PUSH_ACK" : "PULL_ACK", byte_nb);
        }
        
        if(databuf[3] == PKT_PULL_DATA || !bok_push_data)
		continue;

	bok_push_data = false;

	//json parser
	parser_data(databuf, payl_rx, &tmst_rx, &size_rx, &rssi_rx);

	if(tmst_rx == 0)
		continue;
	printf("DEBUG 4");
	//save thing in json file
	save_thing(file, payl_rx);
	printf("DEBUG 5");
	/* PKT_PULL_RESP datagrams header */
	databuf[0] = PROTOCOL_VERSION;
	databuf[1] = 0x00; /* no token */
	databuf[2] = 0x00; /* no token */
	databuf[3] = PKT_PULL_RESP;
	buff_index = 4;

	/* start of JSON structure */
	memcpy((void *)(databuf + buff_index), (void *)"{\"txpk\":{\"imme\":false", 21);
	buff_index += 21;

	/* tmst */
	i = snprintf((char *)(databuf + buff_index), 20, ",\"tmst\":%u", tmst_rx + delay_dw2); // ver qual a formatacao no printf
	if ((i>=0) && (i < 20)) {
		buff_index += i;
	} else {
		MSG("ERROR: snprintf failed line %u\n", (__LINE__ - 4));
		exit(EXIT_FAILURE);
	}
	tmst_rx = 0;

	/* TX frequency */

	i = snprintf((char *)(databuf + buff_index), 20, ",\"freq\":%.6f", f_target);
	if ((i>=0) && (i < 20)) {
		buff_index += i;
	} else {
		MSG("ERROR: snprintf failed line %u\n", (__LINE__ - 4));
		exit(EXIT_FAILURE);
	}

	/* RF channel */
	memcpy((void *)(databuf + buff_index), (void *)",\"rfch\":0", 9);
	buff_index += 9;

	/* TX power */
	i = snprintf((char *)(databuf + buff_index), 12, ",\"powe\":%i", pow);
	if ((i>=0) && (i < 12)) {
		buff_index += i;
	} else {
		MSG("ERROR: snprintf failed line %u\n", (__LINE__ - 4));
		exit(EXIT_FAILURE);
	}

	/* modulation type and parameters */
	if (strcmp(mod, "FSK") == 0) {
		i = snprintf((char *)(databuf + buff_index), 50, ",\"modu\":\"FSK\",\"datr\":%u,\"fdev\":%u", (unsigned int)(br_kbps*1e3), (unsigned int)(fdev_khz*1e3));
		if ((i>=0) && (i < 50)) {
			buff_index += i;
		} else {
			MSG("ERROR: snprintf failed line %u\n", (__LINE__ - 4));
			exit(EXIT_FAILURE);
		}
	} else {
		i = snprintf((char *)(databuf + buff_index), 50, ",\"modu\":\"LORA\",\"datr\":\"SF%iBW%i\",\"codr\":\"4/5\"", sf, bw);
		if ((i>=0) && (i < 50)) {
			buff_index += i;
		} else {
			MSG("ERROR: snprintf failed line %u\n", (__LINE__ - 4));
			exit(EXIT_FAILURE);
		}
	}

	/* signal polarity */
	if (invert) {
		memcpy((void *)(databuf + buff_index), (void *)",\"ipol\":true", 12);
		buff_index += 12;
	} else {
		memcpy((void *)(databuf + buff_index), (void *)",\"ipol\":false", 13);
		buff_index += 13;
	}

	/* Preamble size */
	if (strcmp(mod, "LORA") == 0) {
		memcpy((void *)(databuf + buff_index), (void *)",\"prea\":8", 9);
		buff_index += 9;
	}

	/* payload size */
	i = snprintf((char *)(databuf + buff_index), 12, ",\"size\":%i", payload_size);
	if ((i>=0) && (i < 12)) {
		buff_index += i;
	} else {
		MSG("ERROR: snprintf failed line %u\n", (__LINE__ - 4));
		exit(EXIT_FAILURE);
	}

	/* payload JSON object */
	memcpy((void *)(databuf + buff_index), (void *)",\"data\":\"", 9);
	buff_index += 9;
	payload_index = buff_index; /* keep the value where the payload content start */

	/* fill payload */
	/* payload mac US915 - nao esta encriptado  */
	payload_bin[0] = JOIN_ACCEPT;
	payload_bin[1] = 0xaa;
	payload_bin[2] = 0xaa;
	payload_bin[3] = 0xaa;
	payload_bin[4] = 0xbb;
	payload_bin[5] = 0xbb;
	payload_bin[6] = 0xbb;
	payload_bin[7] = 0xcc;
	payload_bin[8] = 0xcc;
	payload_bin[9] = 0xcc;
	payload_bin[10] = 0xcc;
	payload_bin[11] = 0x00;
	payload_bin[12] = 0x00;
	
	/* compute MIC */
	AES_CMAC_Init( AesCmacCtx );
    AES_CMAC_SetKey( AesCmacCtx, appKey );
    AES_CMAC_Update( AesCmacCtx, payload_bin, 13 & 0xFF );
    AES_CMAC_Final( Mic, AesCmacCtx );
    
    /* fill mic payload */
    payload_bin[13] = Mic[0];
    payload_bin[14] = Mic[1];
    payload_bin[15] = Mic[2];
    payload_bin[16] = Mic[3];
	
	
	memset(AesContext.ksch, '\0', 240);
	aes_set_key(appKey, 16, &AesContext);

	aes_decrypt( (const uint8_t*) &payload_bin[1], &payload_bin_dec[1], &AesContext);
	payload_bin_dec[0] = JOIN_ACCEPT;
	
	/* payload place-holder & end of JSON structure */
	x = bin_to_b64(payload_bin_dec, payload_size, payload_b64, sizeof payload_b64);
	//x = bin_to_b64(payload_bin, payload_size, payload_b64, sizeof payload_b64);
	if (x >= 0) {
		memcpy((void *)(databuf + payload_index), (void *)payload_b64, x);
		buff_index += x;
	} else {
		MSG("ERROR: bin_to_b64 failed line %u\n", (__LINE__ - 4));
		exit(EXIT_FAILURE);
	}

	/* Close JSON structure */
	memcpy((void *)(databuf + buff_index), (void *)"\"}}", 3);
	buff_index += 3; /* ends up being the total length of payload */

	/* main loop */
	for (i = 0; i < repeat; ++i) {
		/* add some artificial latency */
		//usleep(30000); /* 30 ms */

		/* send packet to the gateway */
		byte_nb = sendto(sock, (void *)databuf, buff_index, 0, (struct sockaddr *)&dist_addr, addr_len);
		if (byte_nb == -1) {
			MSG("WARNING: sendto returned an error %s\n", strerror(errno));
		} else {
			MSG("INFO: packet #%i sent successfully\n", i);
		}

		/* wait inter-packet delay */
		usleep(delay * 1000);

		/* exit loop on user signals */
		if ((quit_sig == 1) || (exit_sig == 1)) {
			break;
		}
	}
    }
    exit(EXIT_SUCCESS);
}

/* --- EOF ------------------------------------------------------------------ */
