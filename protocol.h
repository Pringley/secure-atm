#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cassert>
#include <cstring>
#include <string>
#include <sstream>
// Crypto++ headers
#include <base64.h>
#include <aes.h>
#include <osrng.h>
#include <hmac.h>
#include <sha.h>
#include <hex.h>

#define KEY_SIZE (256 / 8)

#define PACKET_SIZE 1024
#define FIELD_SIZE  128
#define FIELDS 8
#define PACKET_SIG_SIZE  (512 / 8)
#define PACKET_DATA_SIZE (PACKET_SIZE - PACKET_SIG_SIZE)
#define PACKET_SIG_POS   PACKET_DATA_SIZE

#define INVALID_MESSAGE_TYPE -2
#define NULL_MESSAGE_ID 0
#define ERROR_MESSAGE_ID -1
#define NONCE_REQUEST_ID 1
#define LOGIN_REQUEST_ID 2
#define BALANCE_REQUEST_ID 3
#define WITHDRAW_REQUEST_ID 4
#define TRANSFER_REQUEST_ID 5
#define NONCE_RESPONSE_ID 51
#define LOGIN_RESPONSE_ID 52
#define BALANCE_RESPONSE_ID 53
#define WITHDRAW_RESPONSE_ID 54
#define TRANSFER_RESPONSE_ID 55

#define GENERIC_ERROR 0
#define REQUEST_ERROR 1
#define LOGIN_ERROR 2
#define AUTH_FAILURE 3
#define INSUFFICIENT_FUNDS 4

int valid_message_types[] = {0, -1, 1, 2, 3, 4, 5, 51, 52, 53, 54, 55};
int valid_message_types_size = 12;
int valid_error_types[] = {0, 1, 2, 3, 4};
int valid_error_types_size = 5;

typedef char Packet [PACKET_SIZE];
typedef char DataField [FIELD_SIZE];
typedef const char *Field;

struct error_message_t {
    int error_code;
    std::string error_message;
    DataField atm_nonce;
    DataField bank_nonce;
};

struct nonce_request_t {
    DataField atm_nonce;
};
struct nonce_response_t {
    DataField atm_nonce;
    DataField bank_nonce;
};

struct login_request_t {
    DataField atm_nonce;
    DataField bank_nonce;
    std::string username;
    std::string card;
    std::string pin;
};
struct login_response_t {
    DataField atm_nonce;
    DataField bank_nonce;
    DataField auth_token;
};

struct balance_request_t {
    DataField atm_nonce;
    DataField bank_nonce;
    DataField auth_token;
};
struct balance_response_t {
    DataField atm_nonce;
    DataField bank_nonce;
    unsigned int balance;
};

struct withdraw_request_t {
    DataField atm_nonce;
    DataField bank_nonce;
    DataField auth_token;
    unsigned int amount;
};
struct withdraw_response_t {
    DataField atm_nonce;
    DataField bank_nonce;
};

struct transfer_request_t {
    DataField atm_nonce;
    DataField bank_nonce;
    DataField auth_token;
    std::string destination;
    unsigned int amount;
};
struct transfer_response_t {
    DataField atm_nonce;
    DataField bank_nonce;
};

// PUBLIC -- encoder functions
bool encode_null_message(Packet &packet);
bool encode_error_message(Packet &packet, const error_message_t &msg);
bool encode_nonce_request(Packet &packet, const nonce_request_t &msg);
bool encode_login_request(Packet &packet, const login_request_t &msg);
bool encode_balance_request(Packet &packet, const balance_request_t &msg);
bool encode_withdraw_request(Packet &packet, const withdraw_request_t &msg);
bool encode_transfer_request(Packet &packet, const transfer_request_t &msg);
bool encode_login_response(Packet &packet, const login_response_t &msg);
bool encode_balance_response(Packet &packet, const balance_response_t &msg);
bool encode_withdraw_response(Packet &packet, const withdraw_response_t &msg);
bool encode_transfer_response(Packet &packet, const transfer_response_t &msg);

// PUBLIC -- message type checker
int get_message_type(Packet const &packet);

// PUBLIC -- decoder functions
bool decode_error_message(Packet const &packet, error_message_t &msg);
bool decode_nonce_request(Packet const &packet, nonce_request_t &msg);
bool decode_login_request(Packet const &packet, login_request_t &msg);
bool decode_balance_request(Packet const &packet, balance_request_t &msg);
bool decode_withdraw_request(Packet const &packet, withdraw_request_t &msg);
bool decode_transfer_request(Packet const &packet, transfer_request_t &msg);
bool decode_login_response(Packet const &packet, login_response_t &msg);
bool decode_balance_response(Packet const &packet, balance_response_t &msg);
bool decode_withdraw_response(Packet const &packet, withdraw_response_t &msg);
bool decode_transfer_response(Packet const &packet, transfer_response_t &msg);

// PUBLIC -- encryption wrappers
void encrypt_packet(Packet &packet, const char *key);
bool decrypt_packet(Packet &packet, const char *key);
void randomize(char *destination, size_t amount);

/********************
 * HELPER FUNCTIONS *
 ********************/

bool validate_message_type(Packet const &packet, int expected_type);
void randomize_remaining_fields(Packet &packet, size_t start);
bool get_int_field(Packet const &packet, int field, int &result);
bool get_unsigned_int_field(Packet const &packet, int field, unsigned int &result);
bool get_str_field(Packet const &packet, int field, std::string &result);
bool get_dat_field(Packet const &packet, int field, DataField &result);
bool set_int_field(Packet &packet, int field, int value);
bool set_unsigned_int_field(Packet &packet, int field, unsigned int value);
bool set_str_field(Packet &packet, int field, std::string const &value);
bool set_dat_field(Packet &packet, int field, DataField const &value);
char *get_field(Packet &packet, int field);
const char *get_field(Packet const &packet, int field);
bool int_to_field(int i, char *field);
bool field_to_int(const char *field, int &i);
bool field_to_unsigned_int(const char *field, unsigned int &i);
bool string_to_field(std::string const &string, char *field);
bool field_to_string(const char *field, std::string &string);

int get_message_type(Packet const &packet) {
    int message_type;
    if(!get_int_field(packet, 0, message_type)) { return INVALID_MESSAGE_TYPE; }
    for(int i = 0; i < valid_message_types_size; i++) {
        if(message_type == valid_message_types[i]) {
            return message_type;
        }
    }
    return INVALID_MESSAGE_TYPE;
}

bool encode_null_message(Packet &packet) {
    if(!set_int_field(packet, 0, NULL_MESSAGE_ID)) { return false; }
    randomize_remaining_fields(packet, 1);
    return true;
}

bool encode_error_message(Packet &packet, const error_message_t &msg) {
    if(!set_int_field(packet, 0, ERROR_MESSAGE_ID)) { return false; }
    if(!set_int_field(packet, 1, msg.error_code)) { return false; }
    if(!set_str_field(packet, 2, msg.error_message)) { return false; }
    if(!set_dat_field(packet, 3, msg.atm_nonce)) { return false; }
    if(!set_dat_field(packet, 4, msg.bank_nonce)) { return false; }
    randomize_remaining_fields(packet, 5);
    return true;
}

bool decode_error_message(Packet const &packet, error_message_t &msg) {
    if(!validate_message_type(packet, ERROR_MESSAGE_ID)) { return false; }
    if(!get_int_field(packet, 1, msg.error_code)) { return false; }
    if(!get_str_field(packet, 2, msg.error_message)) { return false; }
    if(!get_dat_field(packet, 3, msg.atm_nonce)) { return false; }
    if(!get_dat_field(packet, 4, msg.bank_nonce)) { return false; }
    return true;
}

bool encode_nonce_request(Packet &packet, const nonce_request_t &msg) {
    if(!set_int_field(packet, 0, NONCE_REQUEST_ID)) { return false; }
    if(!set_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    randomize_remaining_fields(packet, 2);
    return true;
}

bool decode_nonce_request(Packet const &packet, nonce_request_t &msg) {
    if(!validate_message_type(packet, NONCE_REQUEST_ID)) { return false; }
    if(!get_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    return true;
}

bool encode_login_request(Packet &packet, const login_request_t &msg) {
    if(!set_int_field(packet, 0, LOGIN_REQUEST_ID)) { return false; }
    if(!set_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    if(!set_dat_field(packet, 2, msg.bank_nonce)) { return false; }
    if(!set_str_field(packet, 3, msg.username)) { return false; }
    if(!set_str_field(packet, 4, msg.card)) { return false; }
    if(!set_str_field(packet, 5, msg.pin)) { return false; }
    randomize_remaining_fields(packet, 6);
    return true;
}

bool decode_login_request(Packet const &packet, login_request_t &msg) {
    if(!validate_message_type(packet, LOGIN_REQUEST_ID)) { return false; }
    if(!get_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    if(!get_dat_field(packet, 2, msg.bank_nonce)) { return false; }
    if(!get_str_field(packet, 3, msg.username)) { return false; }
    if(!get_str_field(packet, 4, msg.card)) { return false; }
    if(!get_str_field(packet, 5, msg.pin)) { return false; }
    return true;
}

bool encode_balance_request(Packet &packet, const balance_request_t &msg) {
    if(!set_int_field(packet, 0, BALANCE_REQUEST_ID)) { return false; }
    if(!set_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    if(!set_dat_field(packet, 2, msg.bank_nonce)) { return false; }
    if(!set_dat_field(packet, 3, msg.auth_token)) { return false; }
    randomize_remaining_fields(packet, 4);
    return true;
}

bool decode_balance_request(Packet const &packet, balance_request_t &msg) {
    if(!validate_message_type(packet, BALANCE_REQUEST_ID)) { return false; }
    if(!get_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    if(!get_dat_field(packet, 2, msg.bank_nonce)) { return false; }
    if(!get_dat_field(packet, 3, msg.auth_token)) { return false; }
    return true;
}

bool encode_withdraw_request(Packet &packet, const withdraw_request_t &msg) {
    if(!set_int_field(packet, 0, WITHDRAW_REQUEST_ID)) { return false; }
    if(!set_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    if(!set_dat_field(packet, 2, msg.bank_nonce)) { return false; }
    if(!set_dat_field(packet, 3, msg.auth_token)) { return false; }
    if(!set_unsigned_int_field(packet, 4, msg.amount)) { return false; }
    randomize_remaining_fields(packet, 5);
    return true;
}

bool decode_withdraw_request(Packet const &packet, withdraw_request_t &msg) {
    if(!validate_message_type(packet, WITHDRAW_REQUEST_ID)) { return false; }
    if(!get_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    if(!get_dat_field(packet, 2, msg.bank_nonce)) { return false; }
    if(!get_dat_field(packet, 3, msg.auth_token)) { return false; }
    if(!get_unsigned_int_field(packet, 4, msg.amount)) { return false; }
    return true;
}

bool encode_transfer_request(Packet &packet, const transfer_request_t &msg) {
    if(!set_int_field(packet, 0, TRANSFER_REQUEST_ID)) { return false; }
    if(!set_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    if(!set_dat_field(packet, 2, msg.bank_nonce)) { return false; }
    if(!set_dat_field(packet, 3, msg.auth_token)) { return false; }
    if(!set_str_field(packet, 4, msg.destination)) { return false; }
    if(!set_unsigned_int_field(packet, 5, msg.amount)) { return false; }
    randomize_remaining_fields(packet, 6);
    return true;
}

bool decode_transfer_request(Packet const &packet, transfer_request_t &msg) {
    if(!validate_message_type(packet, TRANSFER_REQUEST_ID)) { return false; }
    if(!get_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    if(!get_dat_field(packet, 2, msg.bank_nonce)) { return false; }
    if(!get_dat_field(packet, 3, msg.auth_token)) { return false; }
    if(!get_str_field(packet, 4, msg.destination)) { return false; }
    if(!get_unsigned_int_field(packet, 5, msg.amount)) { return false; }
    return true;
}

bool encode_nonce_response(Packet &packet, const nonce_response_t &msg) {
    if(!set_int_field(packet, 0, NONCE_RESPONSE_ID)) { return false; }
    if(!set_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    if(!set_dat_field(packet, 2, msg.bank_nonce)) { return false; }
    randomize_remaining_fields(packet, 3);
    return true;
}

bool decode_nonce_response(Packet const &packet, nonce_response_t &msg) {
    if(!validate_message_type(packet, NONCE_RESPONSE_ID)) { return false; }
    if(!get_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    if(!get_dat_field(packet, 2, msg.bank_nonce)) { return false; }
    return true;
}


bool encode_login_response(Packet &packet, const login_response_t &msg) {
    if(!set_int_field(packet, 0, LOGIN_RESPONSE_ID)) { return false; }
    if(!set_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    if(!set_dat_field(packet, 2, msg.bank_nonce)) { return false; }
    if(!set_dat_field(packet, 3, msg.auth_token)) { return false; }
    randomize_remaining_fields(packet, 4);
    return true;
}

bool decode_login_response(Packet const &packet, login_response_t &msg) {
    if(!validate_message_type(packet, LOGIN_RESPONSE_ID)) { return false; }
    if(!get_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    if(!get_dat_field(packet, 2, msg.bank_nonce)) { return false; }
    if(!get_dat_field(packet, 3, msg.auth_token)) { return false; }
    return true;
}

bool encode_balance_response(Packet &packet, const balance_response_t &msg) {
    if(!set_int_field(packet, 0, BALANCE_RESPONSE_ID)) { return false; }
    if(!set_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    if(!set_dat_field(packet, 2, msg.bank_nonce)) { return false; }
    if(!set_unsigned_int_field(packet, 3, msg.balance)) { return false; }
    randomize_remaining_fields(packet, 4);
    return true;
}

bool decode_balance_response(Packet const &packet, balance_response_t &msg) {
    if(!validate_message_type(packet, BALANCE_RESPONSE_ID)) { return false; }
    if(!get_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    if(!get_dat_field(packet, 2, msg.bank_nonce)) { return false; }
    if(!get_unsigned_int_field(packet, 3, msg.balance)) { return false; }
    return true;
}

bool encode_withdraw_response(Packet &packet, const withdraw_response_t &msg) {
    if(!set_int_field(packet, 0, WITHDRAW_RESPONSE_ID)) { return false; }
    if(!set_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    if(!set_dat_field(packet, 2, msg.bank_nonce)) { return false; }
    randomize_remaining_fields(packet, 3);
    return true;
}

bool decode_withdraw_response(Packet const &packet, withdraw_response_t &msg) {
    if(!validate_message_type(packet, WITHDRAW_RESPONSE_ID)) { return false; }
    if(!get_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    if(!get_dat_field(packet, 2, msg.bank_nonce)) { return false; }
    return true;
}

bool encode_transfer_response(Packet &packet, const transfer_response_t &msg) {
    if(!set_int_field(packet, 0, TRANSFER_RESPONSE_ID)) { return false; }
    if(!set_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    if(!set_dat_field(packet, 2, msg.bank_nonce)) { return false; }
    randomize_remaining_fields(packet, 3);
    return true;
}

bool decode_transfer_response(Packet const &packet, transfer_response_t &msg) {
    if(!validate_message_type(packet, TRANSFER_RESPONSE_ID)) { return false; }
    if(!get_dat_field(packet, 1, msg.atm_nonce)) { return false; }
    if(!get_dat_field(packet, 2, msg.bank_nonce)) { return false; }
    return true;
}

bool validate_message_type(Packet const &packet, int expected_type) {
    int message_type;
    if(!get_int_field(packet, 0, message_type)) { return false; }
    return message_type == expected_type;
}

void randomize_remaining_fields(Packet &packet, size_t start) {
    char *start_ptr = packet + start * FIELD_SIZE;
    size_t padding_size = (FIELDS - start) * FIELD_SIZE;
    randomize(start_ptr, padding_size);
}

bool get_int_field(Packet const &packet, int field, int &result) {
    const char *field_ptr = get_field(packet, field);
    if(!field_to_int(field_ptr, result)) { return false; }
    return true;
}

bool get_unsigned_int_field(Packet const &packet, int field, unsigned int &result) {
    const char *field_ptr = get_field(packet, field);
    if(!field_to_unsigned_int(field_ptr, result)) { return false; }
    return true;
}

bool get_str_field(Packet const &packet, int field, std::string &result) {
    const char *field_ptr = get_field(packet, field);
    if(!field_to_string(field_ptr, result)) { return false; }
    return true;
}

bool get_dat_field(Packet const &packet, int field, DataField &result) {
    const char *field_ptr = get_field(packet, field);
    memcpy(result, field_ptr, FIELD_SIZE);
    return true;
}

bool set_int_field(Packet &packet, int field, int value) {
    char *field_ptr = get_field(packet, field);
    if(!int_to_field(value, field_ptr)) { return false; }
    return true;
}

bool set_unsigned_int_field(Packet &packet, int field, unsigned int value) {
    char *field_ptr = get_field(packet, field);
    if(!int_to_field(value, field_ptr)) { return false; }
    return true;
}

bool set_str_field(Packet &packet, int field, std::string const &value) {
    char *field_ptr = get_field(packet, field);
    if(!string_to_field(value, field_ptr)) { return false; }
    return true;
}

bool set_dat_field(Packet &packet, int field, DataField const &value) {
    char *field_ptr = get_field(packet, field);
    memcpy(field_ptr, value, FIELD_SIZE);
    return true;
}

char *get_field(Packet &packet, int field) {
    return packet + field * FIELD_SIZE;
}

const char *get_field(Packet const &packet, int field) {
    return packet + field * FIELD_SIZE;
}

bool int_to_field(int i, char *field) {
    std::ostringstream oss;
    oss << i;
    if(!string_to_field(oss.str(), field)) { return false; }
    return true;
}

bool field_to_int(const char *field, int &i) {
    // Returns false if the field doesn't contain an integer
    std::string string;
    if(!field_to_string(field, string)) { return false; }
    std::istringstream iss(string);
    iss >> i;
    return !iss.fail();
}

bool field_to_unsigned_int(const char *field, unsigned int &i) {
    // Returns false if the field doesn't contain an unsigned integer
    std::string string;
    if(!field_to_string(field, string)) { return false; }
    std::istringstream iss(string);
    iss >> i;
    return !iss.fail();
}

bool string_to_field(std::string const &string, char *field) {
    // Returns false if the string doesn't fit into a field.
    if (string.size() > FIELD_SIZE) {
        return false;
    }
    memcpy(field, string.c_str(), string.size());
    if (string.size() < FIELD_SIZE) {
        field[string.size()] = '\0';
        size_t padding_size = FIELD_SIZE - string.size() - 1;
        randomize(field + string.size() + 1, padding_size);
    }
    return true;
}

bool field_to_string(const char *field, std::string &string) {
    // Returns false if the field doesn't seem to contain a string.
    size_t field_size = 0;
    while (field[field_size] != '\0' && field_size < FIELD_SIZE) {
        field_size++;
    }
    string = std::string(field, field_size);
    return field[field_size] == '\0';
}

void decode_key(char *dest) {
    CryptoPP::Base64Decoder dec;

    // PRIVATE_SHARED_KEY_BASE64 is #define'd via the command line
    const char *base64 = PRIVATE_SHARED_KEY_BASE64;

    while (*base64)
        dec.Put(*(base64++));
    dec.MessageEnd();

    // TODO: ensure no buffer overflows
    while (dec.Get(*(byte *)dest))
        dest++;
}

typedef CryptoPP::HMAC<CryptoPP::SHA512> HMAC_SHA512;

void encrypt_packet(Packet &packet, const char *key) {

    // generate HMAC in end of packet
    HMAC_SHA512 hmac((const byte *)key, KEY_SIZE);
    hmac.Update((byte *)packet, PACKET_DATA_SIZE);
    hmac.Final((byte *)packet + PACKET_SIG_POS);

    // encrypt the whole packet
    byte *ptr = (byte *)packet;
    CryptoPP::AES::Encryption enc((const byte *)key, KEY_SIZE);

    assert(PACKET_SIZE / enc.BlockSize() == 0);
    for (unsigned i = 0; i < PACKET_SIZE; i += enc.BlockSize()) {
        enc.ProcessBlock(ptr);
        ptr += enc.BlockSize();
    }
}

void dump_hex(const byte *arr, size_t len)
{
    CryptoPP::HexEncoder enc;

    enc.Put(arr, len);
    enc.MessageEnd();
    
    byte ch;
    while (enc.Get(ch))
        putchar(ch);
    putchar('\n');
}

bool decrypt_packet(Packet &packet, const char *key) {
    byte digest[PACKET_SIG_SIZE];

    // decrypt whole packet
    byte *ptr = (byte *)packet;
    CryptoPP::AES::Decryption dec((const byte *)key, KEY_SIZE);

    assert(PACKET_SIZE / dec.BlockSize() == 0);
    for (unsigned i = 0; i < PACKET_SIZE; i += dec.BlockSize()) {
        dec.ProcessBlock(ptr);
        ptr += dec.BlockSize();
    }

    // generate HMAC of packet
    HMAC_SHA512 hmac((const byte *)key, KEY_SIZE);
    hmac.Update((byte *)packet, PACKET_DATA_SIZE);
    hmac.Final(digest);

    //dump_hex((byte *)packet + PACKET_SIG_POS, PACKET_SIG_SIZE);
    //dump_hex(digest, PACKET_SIG_SIZE);

    // compare with decrypted HMAC
    return memcmp(digest, (byte *)packet + PACKET_SIG_POS, PACKET_SIG_SIZE);
}

void randomize(char *destination, size_t amount) {
    static CryptoPP::AutoSeededRandomPool rng;

    rng.GenerateBlock((byte *)destination, amount);
}

#endif
