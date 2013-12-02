#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstring>
#include <string>
#include <sstream>

#define PACKET_SIZE 1024
#define FIELD_SIZE  128
#define FIELDS 8

#define NULL_MESSAGE_ID 0
#define ERROR_MESSAGE_ID -1
#define LOGIN_REQUEST_ID 1
#define BALANCE_REQUEST_ID 2
#define WITHDRAW_REQUEST_ID 3
#define TRANSFER_REQUEST_ID 4
#define LOGIN_RESPONSE_ID 51
#define BALANCE_RESPONSE_ID 52
#define WITHDRAW_RESPONSE_ID 53
#define TRANSFER_RESPONSE_ID 54

#define GENERIC_ERROR 0
#define REQUEST_ERROR 1
#define LOGIN_ERROR 2
#define AUTH_FAILURE 3
#define INSUFFICIENT_FUNDS 4

typedef char Packet [PACKET_SIZE];
typedef char DataField [FIELD_SIZE];
typedef const char *Field;

bool validate_message_type(Packet const &packet);

bool get_int_field(Packet const &packet, int field, int &result);
bool get_str_field(Packet const &packet, int field, std::string &result);
bool get_dat_field(Packet const &packet, int field, DataField &result);

bool set_int_field(Packet &packet, int field, int value);
bool set_str_field(Packet &packet, int field, std::string const &value);
bool set_dat_field(Packet &packet, int field, DataField const &value);

char *get_field(Packet &packet, int field);
const char *get_field(Packet const &packet, int field);

bool int_to_field(int i, char *field);
bool field_to_int(const char *field, int &i);
bool field_to_unsigned_int(const char *field, unsigned int &i);

bool string_to_field(std::string const &string, char *field);
bool field_to_string(const char *field, std::string &string);

// Encryption wrappers
void encrypt_packet(Packet const &plaintext, Packet &ciphertext);
void decrypt_packet(Packet const &ciphertext, Packet &plaintext);
void randomize(char *destination, size_t amount);

bool validate_message_type(Packet const &packet) {
    int message_type;
    if(!get_int_field(packet, 0, message_type)) { return false; }
    return true;
}

bool get_int_field(Packet const &packet, int field, int &result) {
    const char *field_ptr = get_field(packet, field);
    if(!field_to_int(field_ptr, result)) { return false; }
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

// stub (should use #define'd 256-bit secret)
void encrypt_packet(Packet const &plaintext, Packet &ciphertext) {
}

// stub (should use #define'd 256-bit secret)
void decrypt_packet(Packet const &ciphertext, Packet &plaintext) {
}

// stub
void randomize(char *destination, size_t amount) {
}

#endif
