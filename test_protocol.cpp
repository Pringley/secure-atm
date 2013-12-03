#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cassert>
#include "protocol.h"

void test_login_request() {
    login_request_t msg;
    msg.atm_nonce[12] = 'z';
    msg.bank_nonce[7] = 'f';
    msg.username = "alice";
    msg.card = "31415-926535";
    msg.pin = "1234";

    int rc;

    Packet packet;
    rc = encode_login_request(packet, msg);
    assert(rc);

    std::string username;
    rc = get_str_field(packet, 3, username);
    assert(rc);
    assert(username == msg.username);

    login_request_t dec;
    rc = decode_login_request(packet, dec);
    assert(rc);

    assert(memcmp(msg.atm_nonce, dec.atm_nonce, FIELD_SIZE) == 0);
    assert(memcmp(msg.bank_nonce, dec.bank_nonce, FIELD_SIZE) == 0);
    assert(msg.username == dec.username);
    assert(msg.card == dec.card);
    assert(msg.pin == dec.pin);
}

void test_balance_request() {
    balance_request_t msg;
    msg.atm_nonce[12] = 'z';
    msg.bank_nonce[7] = 'f';
    msg.auth_token[3] = 's';

    int rc;

    Packet packet;
    rc = encode_balance_request(packet, msg);
    assert(rc);

    balance_request_t dec;
    rc = decode_balance_request(packet, dec);
    assert(rc);

    assert(memcmp(msg.atm_nonce, dec.atm_nonce, FIELD_SIZE) == 0);
    assert(memcmp(msg.bank_nonce, dec.bank_nonce, FIELD_SIZE) == 0);
    assert(memcmp(msg.auth_token, dec.auth_token, FIELD_SIZE) == 0);
}


void test_withdraw_request() {
    withdraw_request_t msg;
    msg.atm_nonce[12] = 'z';
    msg.bank_nonce[7] = 'f';
    msg.auth_token[3] = 's';
    msg.amount = 12;

    int rc;

    Packet packet;
    rc = encode_withdraw_request(packet, msg);
    assert(rc);

    withdraw_request_t dec;
    rc = decode_withdraw_request(packet, dec);
    assert(rc);

    assert(memcmp(msg.atm_nonce, dec.atm_nonce, FIELD_SIZE) == 0);
    assert(memcmp(msg.bank_nonce, dec.bank_nonce, FIELD_SIZE) == 0);
    assert(memcmp(msg.auth_token, dec.auth_token, FIELD_SIZE) == 0);
    assert(msg.amount == dec.amount);
}

void test_nonce_request() {
    nonce_request_t msg;
    msg.atm_nonce[12] = 'z';
    int rc;
    Packet packet;
    rc = encode_nonce_request(packet, msg);
    assert(rc);
    nonce_request_t dec;
    rc = decode_nonce_request(packet, dec);
    assert(rc);
    assert(memcmp(msg.atm_nonce, dec.atm_nonce, FIELD_SIZE) == 0);
}

void test_transfer_request() {
    transfer_request_t msg;
    msg.atm_nonce[12] = 'z';
    msg.bank_nonce[7] = 'f';
    msg.auth_token[3] = 's';
    msg.amount = 12;
    msg.destination = "zanzibar";
    int rc;
    Packet packet;
    rc = encode_transfer_request(packet, msg);
    assert(rc);
    transfer_request_t dec;
    rc = decode_transfer_request(packet, dec);
    assert(rc);
    assert(memcmp(msg.atm_nonce, dec.atm_nonce, FIELD_SIZE) == 0);
    assert(memcmp(msg.bank_nonce, dec.bank_nonce, FIELD_SIZE) == 0);
    assert(memcmp(msg.auth_token, dec.auth_token, FIELD_SIZE) == 0);
    assert(msg.amount == dec.amount);
    assert(msg.destination == dec.destination);
}

void test_login_response() {
    login_response_t msg;
    msg.atm_nonce[12] = 'z';
    msg.bank_nonce[7] = 'f';
    msg.auth_token[3] = 's';
    int rc;
    Packet packet;
    rc = encode_login_response(packet, msg);
    assert(rc);
    login_response_t dec;
    rc = decode_login_response(packet, dec);
    assert(rc);
    assert(memcmp(msg.atm_nonce, dec.atm_nonce, FIELD_SIZE) == 0);
    assert(memcmp(msg.bank_nonce, dec.bank_nonce, FIELD_SIZE) == 0);
    assert(memcmp(msg.auth_token, dec.auth_token, FIELD_SIZE) == 0);
}


void test_balance_response() {
    balance_response_t msg;
    msg.atm_nonce[12] = 'z';
    msg.bank_nonce[7] = 'f';
    msg.balance = 3;
    int rc;
    Packet packet;
    rc = encode_balance_response(packet, msg);
    assert(rc);
    balance_response_t dec;
    rc = decode_balance_response(packet, dec);
    assert(rc);
    assert(memcmp(msg.atm_nonce, dec.atm_nonce, FIELD_SIZE) == 0);
    assert(memcmp(msg.bank_nonce, dec.bank_nonce, FIELD_SIZE) == 0);
    assert(msg.balance == dec.balance);
}

void test_withdraw_response() {
    withdraw_response_t msg;
    msg.atm_nonce[12] = 'z';
    msg.bank_nonce[7] = 'f';
    int rc;
    Packet packet;
    rc = encode_withdraw_response(packet, msg);
    assert(rc);
    withdraw_response_t dec;
    rc = decode_withdraw_response(packet, dec);
    assert(rc);
    assert(memcmp(msg.atm_nonce, dec.atm_nonce, FIELD_SIZE) == 0);
    assert(memcmp(msg.bank_nonce, dec.bank_nonce, FIELD_SIZE) == 0);
}

void test_transfer_response() {
    transfer_response_t msg;
    msg.atm_nonce[12] = 'z';
    msg.bank_nonce[7] = 'f';
    int rc;
    Packet packet;
    rc = encode_transfer_response(packet, msg);
    assert(rc);
    transfer_response_t dec;
    rc = decode_transfer_response(packet, dec);
    assert(rc);
    assert(memcmp(msg.atm_nonce, dec.atm_nonce, FIELD_SIZE) == 0);
    assert(memcmp(msg.bank_nonce, dec.bank_nonce, FIELD_SIZE) == 0);
}

void test_nonce_response() {
    nonce_response_t msg;
    msg.atm_nonce[12] = 'z';
    msg.bank_nonce[7] = 'f';
    int rc;
    Packet packet;
    rc = encode_nonce_response(packet, msg);
    assert(rc);
    nonce_response_t dec;
    rc = decode_nonce_response(packet, dec);
    assert(rc);
    assert(memcmp(msg.atm_nonce, dec.atm_nonce, FIELD_SIZE) == 0);
    assert(memcmp(msg.bank_nonce, dec.bank_nonce, FIELD_SIZE) == 0);
}


void test_packet_access() {
    int rc;
    Packet packet;
    DataField data1;
    data1[0] = 'b';
    data1[15] = 'z';

    set_int_field(packet, 0, 15);
    set_str_field(packet, 1, "Hello, world");
    set_dat_field(packet, 2, data1);
    set_int_field(packet, 3, 42);

    int i;
    rc = get_int_field(packet, 0, i);
    assert(rc);
    assert(i == 15);

    std::string message;
    rc = get_str_field(packet, 1, message);
    assert(rc);
    assert(message == "Hello, world");

    DataField data2;
    rc = get_dat_field(packet, 2, data2);
    assert(rc);
    assert(memcmp(data1, data2, FIELD_SIZE) == 0);

    unsigned int j;
    rc = get_unsigned_int_field(packet, 3, j);
    assert(rc);
    assert(j == 42);
}

void test_int_field() {
    DataField int_field, sint_field, str_field;
    int i = 23, j = -15, k;
    unsigned int m;
    int_to_field(i, int_field);
    int_to_field(j, sint_field);
    string_to_field("Yo", str_field);

    bool int_success = field_to_int(int_field, k);
    assert(int_success);
    assert(i == k);

    bool sint_success = field_to_int(sint_field, k);
    assert(sint_success);
    assert(j == k);

    bool usint_success = field_to_unsigned_int(int_field, m);
    assert(usint_success);
    assert(i == m);

    // Reading -15 as unsigned should fail
    bool usint_success2 = field_to_unsigned_int(sint_field, m);
    assert(!usint_success2);

    // Reading "Yo" as an int should fail
    bool str_success = field_to_int(str_field, k);
    assert(!str_success);
}

int main(int argc, const char *argv[]) {
    test_int_field();
    test_packet_access();
    test_nonce_request();
    test_login_request();
    test_balance_request();
    test_withdraw_request();
    test_transfer_request();
    test_nonce_response();
    test_login_response();
    test_balance_response();
    test_withdraw_response();
    test_transfer_response();
    return 0;
}
