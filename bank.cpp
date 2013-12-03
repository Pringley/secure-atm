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

#include <string>

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

// Use up a nonce pair, return false if it doesn't exist.
bool pop_nonce_pair(DataField const &atm_nonce, DataField const &bank_nonce);

bool check_auth_token(DataField const &auth_token, std::string &username);

unsigned int get_balance(std::string username);

int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		printf("Usage: bank listen-port\n");
		return -1;
	}
	
	unsigned short ourport = atoi(argv[1]);

    //crypto setup
    char key[KEY_SIZE];
    decode_key(key);

    //mutex setup
    pthread_mutex_init(&EVIL_GLOBAL_STATE_MUTEX, NULL);
	
	//socket setup
	int lsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int opt = 1;
    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
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
            case NONCE_REQUEST_ID:
                handle_nonce(packet, response);
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
		if(PACKET_SIZE != send(csock, (void*)response, PACKET_SIZE, 0))
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
    // Respond to null with null.
    encode_null_message(response);
}

void handle_error(Packet const &packet, Packet &response) {
    // Ignore errors from ATM -- puny ATM!!
    encode_null_message(response);
}

void handle_nonce(Packet const &packet, Packet &response) {
    nonce_request_t msg;
    decode_nonce_request(packet, msg);

    nonce_response_t rmsg;
    // Copy the ATM nonce in the response.
    memcpy(rmsg.atm_nonce, msg.atm_nonce, FIELD_SIZE);
    // Generate a new nonce for the bank.
    randomize(rmsg.bank_nonce, FIELD_SIZE);

    // TODO: store this nonce pair somewhere

    encode_nonce_response(response, rmsg);
}

void handle_login(Packet const &packet, Packet &response) {
    login_request_t msg;
    decode_login_request(packet, msg);

    if(!pop_nonce_pair(msg.atm_nonce, msg.bank_nonce)) {
        error_message_t err;
        err.error_code = REQUEST_ERROR;
        err.error_message = "invalid nonces";
        memcpy(err.atm_nonce, msg.atm_nonce, FIELD_SIZE);
        memcpy(err.bank_nonce, msg.bank_nonce, FIELD_SIZE);
        encode_error_message(response, err);
        return;
    }

    bool verified = true;
    // TODO: actually verify the user's credentials
    // msg.username msg.card msg.pin

    // Send error if verify fails.
    if(!verified) {
        error_message_t err;
        err.error_code = LOGIN_ERROR;
        err.error_message = "could not login";
        memcpy(err.atm_nonce, msg.atm_nonce, FIELD_SIZE);
        memcpy(err.bank_nonce, msg.bank_nonce, FIELD_SIZE);
        encode_error_message(response, err);
        return;
    }

    // On success, send an auth token.
    login_response_t rmsg;
    memcpy(rmsg.atm_nonce, msg.atm_nonce, FIELD_SIZE);
    memcpy(rmsg.bank_nonce, msg.bank_nonce, FIELD_SIZE);
    // Generate a new auth token for the user.
    randomize(rmsg.auth_token, FIELD_SIZE);

    // TODO: store the auth token and username somewhere

    encode_login_response(response, rmsg);
}

void handle_balance(Packet const &packet, Packet &response) {
    balance_request_t msg;
    decode_balance_request(packet, msg);

    // Check nonces.
    if(!pop_nonce_pair(msg.atm_nonce, msg.bank_nonce)) {
        error_message_t err;
        err.error_code = REQUEST_ERROR;
        err.error_message = "invalid nonces";
        memcpy(err.atm_nonce, msg.atm_nonce, FIELD_SIZE);
        memcpy(err.bank_nonce, msg.bank_nonce, FIELD_SIZE);
        encode_error_message(response, err);
        return;
    }

    // Check auth token.
    std::string username;
    if(!check_auth_token(msg.auth_token, username)) {
        error_message_t err;
        err.error_code = AUTH_FAILURE;
        err.error_message = "invalid auth token";
        memcpy(err.atm_nonce, msg.atm_nonce, FIELD_SIZE);
        memcpy(err.bank_nonce, msg.bank_nonce, FIELD_SIZE);
        encode_error_message(response, err);
        return;
    }

    balance_response_t rmsg;
    memcpy(rmsg.atm_nonce, msg.atm_nonce, FIELD_SIZE);
    memcpy(rmsg.bank_nonce, msg.bank_nonce, FIELD_SIZE);
    rmsg.balance = get_balance(username);
    encode_balance_response(response, rmsg);
}

void handle_withdraw(Packet const &packet, Packet &response) {
    withdraw_request_t msg;
    decode_withdraw_request(packet, msg);

    // Check nonces.
    if(!pop_nonce_pair(msg.atm_nonce, msg.bank_nonce)) {
        error_message_t err;
        err.error_code = REQUEST_ERROR;
        err.error_message = "invalid nonces";
        memcpy(err.atm_nonce, msg.atm_nonce, FIELD_SIZE);
        memcpy(err.bank_nonce, msg.bank_nonce, FIELD_SIZE);
        encode_error_message(response, err);
        return;
    }

    // Check auth token.
    std::string username;
    if(!check_auth_token(msg.auth_token, username)) {
        error_message_t err;
        err.error_code = AUTH_FAILURE;
        err.error_message = "invalid auth token";
        memcpy(err.atm_nonce, msg.atm_nonce, FIELD_SIZE);
        memcpy(err.bank_nonce, msg.bank_nonce, FIELD_SIZE);
        encode_error_message(response, err);
        return;
    }

    // TODO: actually withdraw monies and check for errors

    withdraw_response_t rmsg;
    memcpy(rmsg.atm_nonce, msg.atm_nonce, FIELD_SIZE);
    memcpy(rmsg.bank_nonce, msg.bank_nonce, FIELD_SIZE);
    encode_withdraw_response(response, rmsg);
}

void handle_transfer(Packet const &packet, Packet &response) {
    transfer_request_t msg;
    decode_transfer_request(packet, msg);

    // Check nonces.
    if(!pop_nonce_pair(msg.atm_nonce, msg.bank_nonce)) {
        error_message_t err;
        err.error_code = REQUEST_ERROR;
        err.error_message = "invalid nonces";
        memcpy(err.atm_nonce, msg.atm_nonce, FIELD_SIZE);
        memcpy(err.bank_nonce, msg.bank_nonce, FIELD_SIZE);
        encode_error_message(response, err);
        return;
    }

    // Check auth token.
    std::string username;
    if(!check_auth_token(msg.auth_token, username)) {
        error_message_t err;
        err.error_code = AUTH_FAILURE;
        err.error_message = "invalid auth token";
        memcpy(err.atm_nonce, msg.atm_nonce, FIELD_SIZE);
        memcpy(err.bank_nonce, msg.bank_nonce, FIELD_SIZE);
        encode_error_message(response, err);
        return;
    }

    // TODO: actually transfer monies and check for errors

    transfer_response_t rmsg;
    memcpy(rmsg.atm_nonce, msg.atm_nonce, FIELD_SIZE);
    memcpy(rmsg.bank_nonce, msg.bank_nonce, FIELD_SIZE);
    encode_transfer_response(response, rmsg);
}

void handle_invalid(Packet const &packet, Packet &response) {
    error_message_t err;
    err.error_code = GENERIC_ERROR;
    err.error_message = "invalid packet";
    encode_error_message(response, err);
    return;
}

void handle_other(Packet const &packet, Packet &response) {
    error_message_t err;
    err.error_code = GENERIC_ERROR;
    err.error_message = "unexpected message type";
    encode_error_message(response, err);
    return;
}

bool pop_nonce_pair(DataField const &atm_nonce, DataField const &bank_nonce) {
    // TODO: actually write nonce pair popper
    return false;
}

bool check_auth_token(DataField const &auth_token, std::string &username) {
    // TODO: actually write auth token checker
    return false;
}

unsigned int get_balance(std::string username) {
    // TODO: actually write balance checker
    return 42;
}
