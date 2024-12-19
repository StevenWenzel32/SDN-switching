#ifndef NETHEADER_H
#define NETHEADER_H

#include <vector>
#include <array>

using namespace std;

// transport 
// 24 bytes = 192 bits
struct tcpHeader {
    // 2 bytes = 16 bits
    unsigned short srcPort;
    // 2 bytes = 16 bits
    unsigned short destPort;
    // 4 bytes = 32 bits
    unsigned int seqNum;
    // 4 bytes = 32 bits
    unsigned int ackNum;
    // 0.5 bytes = 4 bits, shows the length of the header
    unsigned short DO : 4;
    // 3 bits, not used set to 0
    unsigned short rsv : 3;
    // 1.125 bytes = 9 bits 
    unsigned short flags : 9;
    // 2 bytes = 16 bits 
    unsigned short window;
    // 2 bytes = 16 bits -- can be random junk
    unsigned short checksum;
    // 2 bytes = 16 bits -- not being used
    unsigned short urgent;
    // unsure how to store this for now
    unsigned int* data;
};

// transport 
// 8 bytes = 64 bits
struct udpHeader {
    // 2 bytes = 16 bits
    unsigned short srcPort;
    // 2 bytes = 16 bits
    unsigned short destPort;
    // 2 bytes = 16 bits
    unsigned short length;
    // 2 bytes = 16 bits
    unsigned short checksum;
    // unsure how to store this for now
    unsigned int* data;
};

// use size of the structs to check if the size is about what you want 
// network headers = 40 bytes = 320 bits
struct ipHeader {
    // 0.5 bytes = 4 bits
    unsigned char vers : 4;
    // 1 byte = 8 bits
    // first 6 bits = DS field for the type, last 2 bits = ECN
    unsigned char trafficClass : 6;
    unsigned char ecn : 2;
    // 2.5 bytes = 20 bits
    unsigned int flowLabel : 20;
    // 2 bytes = 16 bits - payload length
    unsigned short length;
    // 1 byte = 8 bits -- the type: udp or tcp
    unsigned char nextHeader;
    // 1 byte = 8 bits 
    unsigned char hopLimit;
    // 16 bytes = 128 bits
    array<unsigned short, 8> srcIp;
    // 16 bytes = 128 bits 
    array<unsigned short, 8> destIp;
    // need to check the next header field to find what transport type it is 
    // either TCP or UDP
    union {
        struct tcpHeader tcp;
        struct udpHeader udp;
    } transportHeader;
};

// data link headers
// 26 bytes = 208 bits without payload
struct ethHeader {
    // 7 bytes = 56 bits
    array<unsigned char, 7> preamble;
    // 1 byte = 8 bits
    unsigned char SFD;
    // 6 bytes = 48 bits
    array<unsigned short, 3> destMac;
    // 6 bytes = 48 bits
    array<unsigned short, 3> srcMac;
    // 2 bytes = 16 bits
    unsigned short length;
    // 46 - 1500 bytes, the data payload which is the ipHeaders
    struct ipHeader ipHeader;
    // 4 bytes = 32 bytes
    unsigned int crc;
};

// function types - actions the snd switch will take
enum FunctionType{SWITCH, ROUTER, NAT, FIREWALL};

// structs to be stored in the match action table
struct MatchAction {
    // port num for firewall
    unsigned short srcPort;
    // ip address for NAT
    array<unsigned short, 8> srcIp;
    // ip address for router
    array<unsigned short, 8> destIp;
    // mac address for switch
    array<unsigned short, 3> destMac;
    FunctionType type;
    // port to put the packet through
    int outputPort;
};

// functions shared between the files
void checkForMatch(struct ethHeader eth, vector<MatchAction> matchActionTable);

#endif