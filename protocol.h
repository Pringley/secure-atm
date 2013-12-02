#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstring>
#include <string>
#include <sstream>

#define PACKET_SIZE 1024
#define FIELD_SIZE  128
#define FIELDS 8

typedef char Packet [PACKET_SIZE];
typedef char Field [FIELD_SIZE];
typedef Field Fields [FIELDS];

void fields_to_packet(Fields const &fields, Packet &packet);
void packet_to_fields(Packet const &packet, Fields &fields);

bool string_to_field(std::string const &string, Field &field);
bool field_to_string(Field const &field, std::string &string);

bool int_to_field(int i, Field &field);
bool field_to_int(Field const &field, int &i);
bool field_to_unsigned_int(Field const &field, unsigned int &i);

// Encryption wrappers
void encrypt_packet(Packet const &plaintext, Packet &ciphertext);
void decrypt_packet(Packet const &ciphertext, Packet &plaintext);
void randomize(char *destination, size_t amount);

void fields_to_packet(Fields const &fields, Packet &packet) {
    for (int i = 0; i < FIELDS; i++) {
        memcpy(packet + i * FIELD_SIZE, fields[i], FIELD_SIZE);
    }
}

void packet_to_fields(Packet const &packet, Fields &fields) {
    for (int i = 0; i < FIELDS; i++) {
        memcpy(fields[i], packet + i * FIELD_SIZE, FIELD_SIZE);
    }
}

bool int_to_field(int i, Field &field) {
    std::ostringstream oss;
    oss << i;
    if(!string_to_field(oss.str(), field)) { return false; }
    return true;
}

bool field_to_int(Field const &field, int &i) {
    // Returns false if the field doesn't contain an integer
    std::string string;
    if(!field_to_string(field, string)) { return false; }
    std::istringstream iss(string);
    iss >> i;
    return !iss.fail();
}

bool field_to_unsigned_int(Field const &field, unsigned int &i) {
    // Returns false if the field doesn't contain an unsigned integer
    std::string string;
    if(!field_to_string(field, string)) { return false; }
    std::istringstream iss(string);
    iss >> i;
    return !iss.fail();
}

bool string_to_field(std::string const &string, Field &field) {
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

bool field_to_string(Field const &field, std::string &string) {
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
