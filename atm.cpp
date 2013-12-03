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
#include <errno.h>

#include <iostream>
#include <fstream>

#include "protocol.h"

char key[KEY_SIZE]; // shared key

// GLOOOBAAAL STAAATE
int sock;
bool sock_alive;
nonce_response_t nonces;
DataField auth_token;
bool logged_in = false;

bool check_logged_in(void);
bool bank_login(const char *user, const char *pin);
bool bank_withdraw(unsigned int amt);
bool bank_transfer(unsigned int amt, const char *user);
void bank_logout(void);

bool get_nonces(nonce_response_t &nonce_response);

bool send_recv(Packet &packet);

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
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
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
    sock_alive = true;
	
	//input loop
	char buf[80];
	while(1)
	{
		printf("atm> ");
		fgets(buf, 79, stdin);
		buf[strlen(buf)-1] = '\0';	//trim off trailing newline

        // Get nonces from Bank.
        if(!get_nonces(nonces)) {
            printf("nonce negotiation failed -- try again please\n");
            continue;
        }
		
		//input parsing
		if(!strcmp(buf, "logout"))
			break;
		char *cmd = strtok(buf, " ");
		if(!strcmp(cmd, "login")) {
            if(check_logged_in()) {
                printf("[atm] already logged in - logging out now\n");
                bank_logout();
            }
            char *user = strtok(NULL, " ");
            if (!user) {
                printf("[atm] usage: login [username]\n");
                continue;
            }
            char *pin = getpass("PIN: ");
            bank_login(user, pin);
		} else if(!strcmp(cmd, "balance")) {
            if(!check_logged_in()) {
                printf("[atm] not logged in\n");
                continue;
            }
            // TODO
        } else if(!strcmp(cmd, "withdraw")) {
            if(!check_logged_in()) {
                printf("[atm] not logged in\n");
                continue;
            }
            char *amt_str = strtok(NULL, " ");
            if(!amt_str) {
                printf("[atm] usage: withdraw [amount]\n");
                continue;
            }
            errno = 0;
            long amt = strtol(amt_str, NULL, 10);
            if (errno || amt <= 0) {
                printf("[atm] usage: withdraw [amount]\n");
                continue;
            }
            if(!bank_withdraw(amt)) {
                printf("[atm] unable to make withdrawal\n");
                continue;
            }
        } else if(!strcmp(cmd, "transfer")) {
            if(!check_logged_in()) {
                printf("[atm] not logged in\n");
                continue;
            }
            char *amt_str = strtok(NULL, " ");
            char *user = strtok(NULL, " ");
            if(!amt_str || !user) {
                printf("[atm] usage: transfer [amount] [username]\n");
                continue;
            }
            errno = 0;
            long amt = strtol(amt_str, NULL, 10);
            if(errno || amt <= 0) {
                printf("[atm] usage: transfer [amount] [username]\n");
                continue;
            }
            if(!bank_transfer(amt, user)) {
                printf("[atm] unable to complete transfer\n");
                continue;
            }
        }

        // if the socket dun broke, exit.
        if(!sock_alive) { break; }
	}

    bank_logout();
	
	//cleanup
	close(sock);
	return 0;
}

bool check_logged_in(void) {
    return logged_in;
}

bool bank_login(const char *user, const char *pin) {
    login_request_t req;
    memcpy(req.atm_nonce, nonces.atm_nonce, FIELD_SIZE);
    memcpy(req.bank_nonce, nonces.bank_nonce, FIELD_SIZE);
    req.username = std::string(user);
    req.pin = std::string(pin);

    // Read card from file in CWD.
    std::fstream file((req.username + ".card").c_str());
    file << req.card;
    file.close();

    Packet packet;
    if(!encode_login_request(packet, req)) {
        std::cerr << "Could not encode login request." << std::endl;
        return false;
    }

    if(!send_recv(packet)) {
        std::cerr << "Could not login -- try again!" << std::endl;
        return false;
    }

    int message_type = get_message_type(packet);
    if(message_type != LOGIN_RESPONSE_ID) {
        std::cerr << "Expected LoginResponse from server." << std::endl;
        return false;
    }

    login_response_t response;
    if(!decode_login_response(packet, response)) {
        std::cerr << "Could not decode server response." << std::endl;
        return false;
    }

    if(memcmp(nonces.atm_nonce, response.atm_nonce, FIELD_SIZE) != 0 ||
       memcmp(nonces.bank_nonce, response.bank_nonce, FIELD_SIZE) != 0) {
        std::cerr << "Possible replay attack! Invalid response." << std::endl;
        return false;
    }

    // store the auth token we got from the server
    memcpy(auth_token, response.auth_token, FIELD_SIZE);
    logged_in = true;

    std::cout << "Login successful." << std::endl;

    return true;
}

void print_transaction_cert(DataField const &atm_nonce, DataField const &bank_nonce) {
}

bool bank_withdraw(unsigned int amt) {
    withdraw_request_t req;
    memcpy(req.atm_nonce, nonces.atm_nonce, FIELD_SIZE);
    memcpy(req.bank_nonce, nonces.bank_nonce, FIELD_SIZE);
    memcpy(req.auth_token, auth_token, FIELD_SIZE);
    req.amount = amt;

    Packet packet;
    if(!encode_withdraw_request(packet, req)) {
        std::cerr << "Could not encode withdraw request." << std::endl;
        return false;
    }

    if(!send_recv(packet)) {
        std::cerr << "Error transmitting withdraw request." << std::endl;
        print_transaction_cert(nonces.atm_nonce, nonces.bank_nonce);
        return false;
    }

    int message_type = get_message_type(packet);
    if(message_type == ERROR_MESSAGE_ID) {
        error_message_t err;
        decode_error_message(packet, err);
        if(err.error_code == AUTH_FAILURE) {
            std::cerr << "Not logged in!" << std::endl;
            return false;
        }
        else if (err.error_code == INSUFFICIENT_FUNDS) {
            std::cerr << "Withdraw failed; insufficient funds." << std::endl;
            return false;
        }
        else {
            std::cerr << "Error: " << err.error_message << std::endl;
            print_transaction_cert(nonces.atm_nonce, nonces.bank_nonce);
            return false;
        }
    }
    if(message_type != WITHDRAW_RESPONSE_ID) {
        std::cerr << "Expected WithdrawResponse from server." << std::endl;
        std::cerr << "Got #" << message_type << std::endl;
        print_transaction_cert(nonces.atm_nonce, nonces.bank_nonce);
        return false;
    }

    withdraw_response_t response;
    if(!decode_withdraw_response(packet, response)) {
        std::cerr << "Could not decode server response." << std::endl;
        print_transaction_cert(nonces.atm_nonce, nonces.bank_nonce);
        return false;
    }

    if(memcmp(nonces.atm_nonce, response.atm_nonce, FIELD_SIZE) != 0 ||
       memcmp(nonces.bank_nonce, response.bank_nonce, FIELD_SIZE) != 0) {
        std::cerr << "Possible replay attack! Invalid response." << std::endl;
        print_transaction_cert(nonces.atm_nonce, nonces.bank_nonce);
        return false;
    }

    std::cout << amt << " withdrawn" << std::endl;

    return true;
}

bool bank_transfer(unsigned int amt, const char *user) {
    transfer_request_t req;
    memcpy(req.atm_nonce, nonces.atm_nonce, FIELD_SIZE);
    memcpy(req.bank_nonce, nonces.bank_nonce, FIELD_SIZE);
    memcpy(req.auth_token, auth_token, FIELD_SIZE);
    req.amount = amt;
    req.destination = std::string(user);

    Packet packet;
    if(!encode_transfer_request(packet, req)) {
        std::cerr << "Could not encode transfer request." << std::endl;
        return false;
    }

    if(!send_recv(packet)) {
        std::cerr << "Error transmitting transfer request." << std::endl;
        print_transaction_cert(nonces.atm_nonce, nonces.bank_nonce);
        return false;
    }

    int message_type = get_message_type(packet);
    if(message_type == ERROR_MESSAGE_ID) {
        error_message_t err;
        decode_error_message(packet, err);
        if(err.error_code == AUTH_FAILURE) {
            std::cerr << "Not logged in!" << std::endl;
            return false;
        }
        else if (err.error_code == INSUFFICIENT_FUNDS) {
            std::cerr << "transfer failed" << std::endl;
            return false;
        }
        else {
            std::cerr << "transfer failed" << std::endl;
            print_transaction_cert(nonces.atm_nonce, nonces.bank_nonce);
            return false;
        }
    }
    if(message_type != TRANSFER_RESPONSE_ID) {
        std::cerr << "Expected TransferResponse from server." << std::endl;
        std::cerr << "Got #" << message_type << std::endl;
        print_transaction_cert(nonces.atm_nonce, nonces.bank_nonce);
        return false;
    }

    transfer_response_t response;
    if(!decode_transfer_response(packet, response)) {
        std::cerr << "Could not decode server response." << std::endl;
        print_transaction_cert(nonces.atm_nonce, nonces.bank_nonce);
        return false;
    }

    if(memcmp(nonces.atm_nonce, response.atm_nonce, FIELD_SIZE) != 0 ||
       memcmp(nonces.bank_nonce, response.bank_nonce, FIELD_SIZE) != 0) {
        std::cerr << "Possible replay attack! Invalid response." << std::endl;
        print_transaction_cert(nonces.atm_nonce, nonces.bank_nonce);
        return false;
    }

    std::cout << amt << " transferred" << std::endl;

    return true;
}

void bank_logout(void) {
    // no notion of "logout" unfortunately
    return;
}

bool get_nonces(nonce_response_t &nonce_response) {
    Packet packet;
    nonce_request_t nr;
    randomize(nr.atm_nonce, FIELD_SIZE);
    encode_nonce_request(packet, nr);
    
    if(!send_recv(packet)) { return false; }

    int message_type = get_message_type(packet);
    if(message_type != NONCE_RESPONSE_ID) {
        printf("received non-nonce packet in response to nonce -- request failed\n");
        return false;
    }
    if(!decode_nonce_response(packet, nonce_response)) { return false; }
    return true;
}

bool send_recv(Packet &packet) {
    encrypt_packet(packet, key);
    if(PACKET_SIZE != send(sock, (void*)packet, PACKET_SIZE, 0))
    {
        printf("fail to send packet\n");
        sock_alive = false;
        return false;
    }
    if(PACKET_SIZE != recv(sock, packet, PACKET_SIZE, 0))
    {
        printf("fail to read packet\n");
        sock_alive = false;
        return false;
    }
    if(!decrypt_packet(packet, key)) {
        printf("rejecting unauthenticated packet\n");
        return false;
    }
    int message_type = get_message_type(packet);
    if(message_type == INVALID_MESSAGE_TYPE) {
        printf("invalid message type received\n");
        return false;
    }
    if(message_type == ERROR_MESSAGE_ID) {
        error_message_t err;
        decode_error_message(packet, err);
        if(err.error_code == GENERIC_ERROR) {
            std::cout << "server error " << err.error_code
                      << ": " << err.error_message << std::endl;
            return false;
        }
    }
    return true;
}
