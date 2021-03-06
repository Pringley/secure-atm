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
#include <vector>
#include <iostream>
#include <map>
#include <fstream>

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

struct AuthInfo {
    std::string username;
    DataField token;
    time_t created;
};
std::vector<AuthInfo> valid_auth_info;

struct UserInfo {
    std::string username;
    std::string pin;
    std::string card;
    unsigned int balance;
};
std::map<std::string, UserInfo> all_users;

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

void store_auth_token(DataField const &auth_token, std::string const &username);

bool check_user_exists(std::string const &username);

void add_user(std::string const &username, unsigned int balance, std::string pin);
bool get_user(UserInfo *dest, std::string const &username);

bool transfer_funds(std::string const &from, std::string const &to, unsigned int amt);
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

    //user setup
    add_user("Alice", 100, "deadbeef");
    add_user("Bob", 50, "deadbeef2.0");
    add_user("Eve", 0, "deadbeeftastic");

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

    time_t last_req, now;
    time(&last_req);
	
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
        
        Packet response;
        bool just_nonce = false;

        if(!decrypt_packet(packet, key)) {
            printf("unauthenticated packet!\n");
            error_message_t err;
            err.error_code = GENERIC_ERROR;
            err.error_message = "packet failed to authenticate";
            encode_error_message(response, err);
        } else {
            int message_type = get_message_type(packet);
            switch(message_type) {
                case NULL_MESSAGE_ID:
                    handle_null(packet, response);
                    break;
                case ERROR_MESSAGE_ID:
                    handle_error(packet, response);
                    break;
                case NONCE_REQUEST_ID:
                    just_nonce = true;
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
        }

        encrypt_packet(response, key);

        // Rate limit requests from each ATM individually.
        // Hopefully prevent some enumeration attacks.
        time(&now);
        if(difftime(now, last_req) < 2) {
            printf("[bank] too fast requests from single ATM\n");
            printf("[bank] taking a quick nap...\n");
            sleep(5);
        }

		//send the new packet back to the client
		if(PACKET_SIZE != send(csock, (void*)response, PACKET_SIZE, 0))
		{
			printf("[bank] fail to send packet\n");
			break;
		}

        if(!just_nonce) {
            time(&last_req);
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
        if (!cmd) {
            continue;
        }
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

    bool verified = false;
    // msg.username msg.card msg.pin
    UserInfo info;
    if(get_user(&info, msg.username)) {
        if(msg.pin == info.pin && msg.card == info.card) {
            verified = true;
        }
    }

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

    // associate the auth token with the user
    store_auth_token(rmsg.auth_token, msg.username);

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

    // Withdraw amount.
    bool res = adjust_balance(username, -msg.amount);
    if(!res) {
        error_message_t err;
        err.error_code = INSUFFICIENT_FUNDS;
        err.error_message = "insufficient funds";
        memcpy(err.atm_nonce, msg.atm_nonce, FIELD_SIZE);
        memcpy(err.bank_nonce, msg.bank_nonce, FIELD_SIZE);
        encode_error_message(response, err);
        return;
    }

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

    // Perform actual transfer.
    bool res = transfer_funds(username, msg.destination, msg.amount);
    if(!res) {
        error_message_t err;
        err.error_code = INSUFFICIENT_FUNDS;
        err.error_message = "insufficient funds";
        memcpy(err.atm_nonce, msg.atm_nonce, FIELD_SIZE);
        memcpy(err.bank_nonce, msg.bank_nonce, FIELD_SIZE);
        encode_error_message(response, err);
        return;
    }

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
    // also looks up username, overwrites the input arg
    pthread_mutex_lock(&EVIL_GLOBAL_STATE_MUTEX);
    bool found = false;
    time_t created;
    for(std::vector<AuthInfo>::iterator i = valid_auth_info.begin();
        i != valid_auth_info.end(); ++i) {
        if(memcmp(i->token, auth_token, FIELD_SIZE) == 0) {
            found = true;
            created = i->created;
            username = i->username;
            break;
        }
    }
    pthread_mutex_unlock(&EVIL_GLOBAL_STATE_MUTEX);
    time_t now;
    time(&now);
    // expire tokens after 5 minutes (300 seconds)
    return found && difftime(now, created) < 300;
    return false;
}

void store_auth_token(DataField const &auth_token, std::string const &username) {
    AuthInfo auth;
    auth.username = username;
    memcpy(auth.token, auth_token, FIELD_SIZE);
    time(&auth.created);

    pthread_mutex_lock(&EVIL_GLOBAL_STATE_MUTEX);
    // expire old token(s)
    for (std::vector<AuthInfo>::iterator i = valid_auth_info.begin();
        i != valid_auth_info.end(); ++i) {
        if (i->username == username) {
            std::cout << "expiring login for " << username << std::endl;
            i = valid_auth_info.erase(i);
            if (i == valid_auth_info.end()) { break; }
        }
    }
    // allow new token
    valid_auth_info.push_back(auth);
    pthread_mutex_unlock(&EVIL_GLOBAL_STATE_MUTEX);
}

void add_user(std::string const &username, unsigned int balance, std::string pin) {
    UserInfo info;

    info.username = username;
    info.pin = pin;
    info.balance = balance;

    std::fstream file((username + ".card").c_str());
    file >> info.card;
    if(file.fail()) {
        std::cerr << "Could not read .card file." << std::endl;
        std::cerr << "User creation failed for " << username << std::endl;
        file.close();
        return;
    }
    file.close();

    all_users[username] = info;
}

bool get_user(UserInfo *dest, std::string const &username) {
    std::map<std::string, UserInfo>::const_iterator it = all_users.find(username);
    if (it == all_users.end())
        return false;

    if (dest)
        *dest = it->second;
    return true;
}

bool check_user_exists(std::string const &username) {
    return get_user(NULL, username);
}

bool adjust_balance_impl(std::string const &username, int delta) {
    UserInfo info;

    if (!get_user(&info, username)) {
        return false;
    }

    if (delta < 0 && info.balance < -delta) {
        return false;
    }

    if (delta > 0 && (long long)delta + (long long)info.balance > (long long)UINT_MAX) {
        return false;
    }

    info.balance += delta;
    all_users[username] = info;
    return true;
}

bool transfer_funds(std::string const &from, std::string const &to, unsigned int amt) {
    pthread_mutex_lock(&EVIL_GLOBAL_STATE_MUTEX);

    bool res = false;
    if(adjust_balance_impl(from, -amt)) {
        if(adjust_balance_impl(to, amt)) {
            res = true;
        } else {
            // undo previous withdrawal
            adjust_balance_impl(from, amt);
        }
    }

    pthread_mutex_unlock(&EVIL_GLOBAL_STATE_MUTEX);

    return res;
}

bool adjust_balance(std::string const &username, int delta) {
	pthread_mutex_lock(&EVIL_GLOBAL_STATE_MUTEX);

	bool res = adjust_balance_impl(username, delta);

	pthread_mutex_unlock(&EVIL_GLOBAL_STATE_MUTEX);

	return res;
}

unsigned int get_balance(std::string const &username) {
    UserInfo info;

    if (!get_user(&info, username)) {
        return false;
    }

    return info.balance;
}
