#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include "protocol.h"

void test_packet_assembly() {
    std::string message = "Hi there";
    int index = 2;

    Fields fields;
    string_to_field(message, fields[index]);

    Packet packet;
    fields_to_packet(fields, packet);

    Fields fields2;
    packet_to_fields(packet, fields2);

    std::string message2;
    field_to_string(fields2[index], message2);

    assert(message == message2);
}

void test_int_field() {
    Field int_field, sint_field, str_field;
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
    test_packet_assembly();
    test_int_field();
    return 0;
}
