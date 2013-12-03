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
#include <errno.h>
#include <time.h>

#include <string>
#include <set>
#include <utility>

#include "protocol.h"

void* client_thread(void* arg);
void* console_thread(void* arg);

/* evil global state */
pthread_mutex_t EVIL_GLOBAL_STATE_MUTEX;

struct NoncePair {
    DataField atm;
    DataField bank;
    time_t created;
};
std::vector<NoncePair> valid_nonce_pairs;

char key[KEY_SIZE]; // shared key

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

void push_nonce_pair(DataField const &atm_nonce, DataField const &bank_nonce);

bool check_auth_token(DataField const &auth_token, std::string &username);

bool check_user_exists(std::string const &username);

bool adjust_balance(std::string const &username, int delta);
unsigned int get_balance(std::string const &username);

int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		printf("Usage: bank listen-port\n");
		return -1;
	}
	
	unsigned short ourport = atoi(argv[1]);

    //crypto setup
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

        if(!decrypt_packet(packet, key)) {
            printf("unauthenticated packet! (ignoring)\n");
            continue;
        }

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

        encrypt_packet(response, key);

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

        char *cmd = strtok(buf, " ");
        if (!strcmp(cmd, "deposit"))
        {
            char *user = strtok(NULL, " ");
            char *amt_str = strtok(NULL, " ");
            if (!user || !amt_str) {
                printf("[bank] usage: deposit [username] [amount]\n");
                continue;
            }
            if (!check_user_exists(user)) {
                printf("[bank] user '%s' doesn't exist\n", user);
                continue;
            }
            errno = 0;
            long amt = strtol(amt_str, NULL, 10);
            if (errno) {
                printf("[bank] usage: deposit [username] [amount]\n");
                continue;
            }
            if (!adjust_balance(user, amt)) {
                printf("[bank] unable to make deposit\n");
                continue;
            }
            unsigned int bal = get_balance(user);
            printf("[bank] new balance of '%s': %u\n", user, bal);
        }
        else if (!strcmp(cmd, "balance"))
        {
            char *user = strtok(NULL, " ");
            if (!user) {
                printf("[bank] usage: balance [username]\n");
                continue;
            }
            if (!check_user_exists(user)) {
                printf("[bank] user '%s' doesn't exist\n", user);
                continue;
            }
            unsigned int bal = get_balance(user);
            printf("[bank] balance of '%s': %u\n", user, bal);
        }
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

    push_nonce_pair(rmsg.atm_nonce, rmsg.bank_nonce);

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
    pthread_mutex_lock(&EVIL_GLOBAL_STATE_MUTEX);
    bool found = false;
    time_t created;
    for(std::vector<NoncePair>::iterator i = valid_nonce_pairs.begin();
        i != valid_nonce_pairs.end(); ++i) {
        if(memcmp(i->atm, atm_nonce, FIELD_SIZE) == 0 &&
           memcmp(i->bank, bank_nonce, FIELD_SIZE) == 0) {
            found = true;
            created = i->created;
            valid_nonce_pairs.erase(i);
            break;
        }
    }
    pthread_mutex_unlock(&EVIL_GLOBAL_STATE_MUTEX);
    time_t now;
    time(&now);
    // expire pairs after 30 seconds
    return found && difftime(now, created) < 30;
}

void push_nonce_pair(DataField const &atm_nonce, DataField const &bank_nonce) {
    NoncePair pair;
    memcpy(pair.atm, atm_nonce, FIELD_SIZE);
    memcpy(pair.bank, bank_nonce, FIELD_SIZE);
    time(&pair.created);

    pthread_mutex_lock(&EVIL_GLOBAL_STATE_MUTEX);
    valid_nonce_pairs.push_back(pair);
    pthread_mutex_unlock(&EVIL_GLOBAL_STATE_MUTEX);
}

bool check_auth_token(DataField const &auth_token, std::string &username) {
    // TODO: actually write auth token checker
    return false;
}

bool check_user_exists(std::string const &username) {
    // NOBODY EXISTS MUAHAHAH
    return false;
}

bool adjust_balance(std::string const &username, int delta) {
    // TODO: actually write balance adjuster
    return true;
}

unsigned int get_balance(std::string const &username) {
    // TODO: actually write balance checker
    return 42;
}
