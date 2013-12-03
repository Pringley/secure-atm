/**
	@file bank.cpp
	@brief Top level bank implementation file
 */
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "protocol.h"

void* client_thread(void* arg);
void* console_thread(void* arg);

/* evil global state */
pthread_mutex_t EVIL_GLOBAL_STATE_MUTEX;

void handle_null(Packet const &packet, Packet &response);
void handle_error(Packet const &packet, Packet &response);
void handle_nonce(Packet const &packet, Packet &response);
void handle_login(Packet const &packet, Packet &response);
void handle_balance(Packet const &packet, Packet &response);
void handle_withdraw(Packet const &packet, Packet &response);
void handle_transfer(Packet const &packet, Packet &response);
void handle_invalid(Packet const &packet, Packet &response);
void handle_other(Packet const &packet, Packet &response);

int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		printf("Usage: bank listen-port\n");
		return -1;
	}
	
	unsigned short ourport = atoi(argv[1]);

    //mutex setup
    pthread_mutex_init(&EVIL_GLOBAL_STATE_MUTEX, NULL);
	
	//socket setup
	int lsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(!lsock)
	{
		printf("fail to create socket\n");
		return -1;
	}
	
	//listening address
	sockaddr_in addr_l;
	addr_l.sin_family = AF_INET;
	addr_l.sin_port = htons(ourport);
	unsigned char* ipaddr = reinterpret_cast<unsigned char*>(&addr_l.sin_addr);
	ipaddr[0] = 127;
	ipaddr[1] = 0;
	ipaddr[2] = 0;
	ipaddr[3] = 1;
	if(0 != bind(lsock, reinterpret_cast<sockaddr*>(&addr_l), sizeof(addr_l)))
	{
		printf("failed to bind socket\n");
		return -1;
	}
	if(0 != listen(lsock, SOMAXCONN))
	{
		printf("failed to listen on socket\n");
		return -1;
	}
	
	pthread_t cthread;
	pthread_create(&cthread, NULL, console_thread, NULL);
	
	//loop forever accepting new connections
	while(1)
	{
		sockaddr_in unused;
		socklen_t size = sizeof(unused);
		int csock = accept(lsock, reinterpret_cast<sockaddr*>(&unused), &size);
		if(csock < 0)	//bad client, skip it
			continue;
			
		pthread_t thread;
		pthread_create(&thread, NULL, client_thread, (void*)csock);
	}
}

void* client_thread(void* arg)
{
	int csock = (int)arg;
	
	printf("[bank] client ID #%d connected\n", csock);
	
	//input loop
	Packet packet;
	while(1)
	{
		//read the packet from the ATM
		if(PACKET_SIZE != recv(csock, packet, PACKET_SIZE, 0))
		{
			printf("[bank] fail to read packet\n");
			break;
		}

        // TODO: decrypt packet

        Packet response;
        int message_type = get_message_type(packet);
        switch(message_type) {
            case NULL_MESSAGE_ID:
                handle_null(packet, response);
                break;
            case ERROR_MESSAGE_ID:
                handle_error(packet, response);
                break;
            case LOGIN_REQUEST_ID:
                handle_login(packet, response);
                break;
            case BALANCE_REQUEST_ID:
                handle_balance(packet, response);
                break;
            case WITHDRAW_REQUEST_ID:
                handle_withdraw(packet, response);
                break;
            case TRANSFER_REQUEST_ID:
                handle_transfer(packet, response);
                break;
            case INVALID_MESSAGE_TYPE:
                handle_invalid(packet, response);
                break;
            default:
                handle_other(packet, response);
        }

        // TODO: encrypt response

		//send the new packet back to the client
		if(PACKET_SIZE != send(csock, (void*)packet, PACKET_SIZE, 0))
		{
			printf("[bank] fail to send packet\n");
			break;
		}

	}

	printf("[bank] client ID #%d disconnected\n", csock);

	close(csock);
	return NULL;
}

void* console_thread(void* arg)
{
	char buf[80];
	while(1)
	{
		printf("bank> ");
		fgets(buf, 79, stdin);
		buf[strlen(buf)-1] = '\0';	//trim off trailing newline
		
		//TODO: your input parsing code has to go here
	}
}

void handle_null(Packet const &packet, Packet &response) {
}

void handle_error(Packet const &packet, Packet &response) {
}

void handle_nonce(Packet const &packet, Packet &response) {
}

void handle_login(Packet const &packet, Packet &response) {
}

void handle_balance(Packet const &packet, Packet &response) {
}

void handle_withdraw(Packet const &packet, Packet &response) {
}

void handle_transfer(Packet const &packet, Packet &response) {
}

void handle_invalid(Packet const &packet, Packet &response) {
}

void handle_other(Packet const &packet, Packet &response) {
}
