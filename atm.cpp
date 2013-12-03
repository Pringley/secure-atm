/**
	@file atm.cpp
	@brief Top level ATM implementation file
 */
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "protocol.h"

char key[KEY_SIZE]; // shared key

bool get_nonces(int sock, nonce_response_t &nonce_response);

int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		printf("Usage: atm proxy-port\n");
		return -1;
	}

  //crypto setup
  decode_key(key);
	
	//socket setup
	unsigned short proxport = atoi(argv[1]);
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(!sock)
	{
		printf("fail to create socket\n");
		return -1;
	}
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(proxport);
	unsigned char* ipaddr = reinterpret_cast<unsigned char*>(&addr.sin_addr);
	ipaddr[0] = 127;
	ipaddr[1] = 0;
	ipaddr[2] = 0;
	ipaddr[3] = 1;
	if(0 != connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)))
	{
		printf("fail to connect to proxy\n");
		return -1;
	}
	
	//input loop
	char buf[80];
	while(1)
	{
		printf("atm> ");
		fgets(buf, 79, stdin);
		buf[strlen(buf)-1] = '\0';	//trim off trailing newline
		
		//input parsing
		if(!strcmp(buf, "logout"))
			break;
		//TODO: other commands
        
        // Get nonces from Bank.
        nonce_response_t nonces;
        if(!get_nonces(sock, nonces)) {
            printf("nonce negotiation failed\n");
            break;
        }

        Packet packet;
        // TODO: send a real request, not a null message
        // use nonces.atm_nonce and nonces.bank_nonce
        encode_null_message(packet);
		
        encrypt_packet(packet, key);
		//send the packet through the proxy to the bank
		if(PACKET_SIZE != send(sock, (void*)packet, PACKET_SIZE, 0))
		{
			printf("fail to send packet\n");
			break;
		}
		
		//TODO: do something with response packet
		if(PACKET_SIZE != recv(sock, packet, PACKET_SIZE, 0))
		{
			printf("fail to read packet\n");
			break;
		}
        if(!decrypt_packet(packet, key)) {
            printf("unauthenticated packet (ignoring)!\n");
            continue;
        }
        int message_type = get_message_type(packet);
        printf("Got a response! %d\n", message_type);
	}
	
	//cleanup
	close(sock);
	return 0;
}
bool get_nonces(int sock, nonce_response_t &nonce_response) {
    Packet packet;
    nonce_request_t nr;
    randomize(nr.atm_nonce, FIELD_SIZE);
    encode_nonce_request(packet, nr);
    encrypt_packet(packet, key);
    
    //send the packet through the proxy to the bank
    if(PACKET_SIZE != send(sock, (void*)packet, PACKET_SIZE, 0))
    {
        printf("fail to send packet\n");
        return false;
    }
    
    while(true) {
        if(PACKET_SIZE != recv(sock, packet, PACKET_SIZE, 0))
        {
            printf("fail to read packet\n");
            return false;
        }
        if(!decrypt_packet(packet, key)) {
            printf("unauthenticated nonce packet! (ignoring)\n");
            continue;
        }
        break;
    }
    int message_type = get_message_type(packet);
    if(message_type != NONCE_RESPONSE_ID) { return false; }
    if(!decode_nonce_response(packet, nonce_response)) { return false; }
    return true;
}

