#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cassert>
#include "protocol.h"

void test_packet_access() {
    int rc;
    Packet packet;
    DataField data1;
    data1[0] = 'b';
    data1[15] = 'z';

    set_int_field(packet, 0, 15);
    set_str_field(packet, 1, "Hello, world");
    set_dat_field(packet, 2, data1);

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
    return 0;
}
