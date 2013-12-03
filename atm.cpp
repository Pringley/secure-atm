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
            printf("nonce negotiation failed\n");
            break;
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
                break;
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
    return false;
}

bool bank_withdraw(unsigned int amt) {
    return false;
}

bool bank_transfer(unsigned int amt, const char *user) {
    return false;
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
    
    //send the packet through the proxy to the bank
    if(PACKET_SIZE != send(sock, (void*)packet, PACKET_SIZE, 0))
    {
        printf("fail to send packet\n");
        return false;
    }
    
    if(!send_recv(packet)) { return false; }

    int message_type = get_message_type(packet);
    if(message_type != NONCE_RESPONSE_ID) { return false; }
    if(!decode_nonce_response(packet, nonce_response)) { return false; }
    return true;
}

bool send_recv(Packet &packet) {
    encrypt_packet(packet, key);
    if(PACKET_SIZE != send(sock, (void*)packet, PACKET_SIZE, 0))
    {
        printf("fail to send packet\n");
        return false;
    }
    if(PACKET_SIZE != recv(sock, packet, PACKET_SIZE, 0))
    {
        printf("fail to read packet\n");
        return false;
    }
    if(!decrypt_packet(packet, key)) {
        printf("rejecting unauthenticated packet\n");
        return false;
    }
    return true;
}
