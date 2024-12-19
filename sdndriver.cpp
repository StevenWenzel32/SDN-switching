#include <iostream>
#include <strings.h>      // bzero
#include <errno.h>        // errno
#include <string.h>       // for memset
#include "networkHeaders.hpp" // for the network header structs
#include <vector>
#include <string>
#include <functional>
#include <cstring>  // Required for memset
#include <array>

using namespace std;

// transport 
// 24 bytes = 192 bits
struct tcpHeader makeTcpHeader(unsigned short srcPort, unsigned short destPort) {
    // header struct to return
    struct tcpHeader tcp;
    // empty msg to send
    unsigned int buffer[12];
    // set the array to 0s
    memset(buffer, 0, sizeof(buffer));
    // 2 bytes = 16 bits
    tcp.srcPort = srcPort;
    // 2 bytes = 16 bits
    tcp.destPort = destPort;
    // 4 bytes = 32 bits
    tcp.seqNum = 0;
    // 4 bytes = 32 bits
    tcp.ackNum = 0;
    // 0.5 bytes = 4 bits, shows the length of the header
    tcp.DO = 0;
    // 3 bits, not used set to 0
    tcp.rsv = 0;
    // 1.125 bytes = 9 bits 
    tcp.flags = 0;
    // 2 bytes = 16 bits 
    tcp.window = 1;
    // 2 bytes = 16 bits -- can be random junk
    tcp.checksum = 0;
    // 2 bytes = 16 bits -- not being used
    tcp.urgent = 0;
    // unsure how to store this for now
    tcp.data = buffer;
    return tcp;
};

// transport 
// 8 bytes = 64 bits
struct udpHeader makeUdpHeader(unsigned short srcPort, unsigned short destPort) {
    // header struct to return
    struct udpHeader udp;
    // empty msg to send
    unsigned int buffer[12];
    // set the array to 0s
    memset(buffer, 0, sizeof(buffer));
    // 2 bytes = 16 bits
    udp.srcPort = srcPort;
    // 2 bytes = 16 bits
    udp.destPort = destPort;
    // 2 bytes = 16 bits
    udp.length = 8;
    // 2 bytes = 16 bits
    udp.checksum = 0;
    // unsure how to store this for now
    udp.data = buffer;
    return udp;
};

// use size of the structs to check if the size is about what you want 
// network headers = 40 bytes = 320 bits
struct ipHeader makeIpHeader(struct tcpHeader tcp, array<unsigned short, 8> srcIp, array<unsigned short, 8> destIp){
    // header struct to return
    struct ipHeader ip;
    // 0.5 bytes = 4 bits
    ip.vers = 0;
    // 1 byte = 8 bits
    // first 6 bits = DS field for the type, last 2 bits = ECN
    ip.trafficClass = 0;
    ip.ecn = 0;
    // 2.5 bytes = 20 bits
    ip.flowLabel = 0;
    // 2 bytes = 16 bits - payload length
    ip.length = 24;
    // 1 byte = 8 bits -- the type: udp or tcp
    // tcp = 6
    ip.nextHeader = 6;
    // 1 byte = 8 bits 
    ip.hopLimit = 5;
    // 16 bytes = 128 bits
    ip.srcIp = srcIp;
    // 16 bytes = 128 bits 
    ip.destIp = destIp;
    // need to check the next header field to find what transport type it is 
    // either TCP or UDP -- unsure how to store this for now
    ip.transportHeader.tcp = tcp;
    return ip;
};

// use size of the structs to check if the size is about what you want 
// network headers = 40 bytes = 320 bits
struct ipHeader makeIpHeader(struct udpHeader udp, array<unsigned short, 8> srcIp, array<unsigned short, 8> destIp){
    // header struct to return
    struct ipHeader ip;
    // 0.5 bytes = 4 bits
    ip.vers = 0;
    // 1 byte = 8 bits
    // first 6 bits = DS field for the type, last 2 bits = ECN
    ip.trafficClass = 0;
    ip.ecn = 0;
    // 2.5 bytes = 20 bits
    ip.flowLabel = 0;
    // 2 bytes = 16 bits - payload length
    ip.length = 24;
    // 1 byte = 8 bits -- the type: udp or tcp
    // udp = 17
    ip.nextHeader = 17;
    // 1 byte = 8 bits 
    ip.hopLimit = 5;
    // 16 bytes = 128 bits
    ip.srcIp = srcIp;
    // 16 bytes = 128 bits 
    ip.destIp = destIp;
    // need to check the next header field to find what transport type it is 
    // either TCP or UDP -- unsure how to store this for now
    ip.transportHeader.udp = udp;
    return ip;
};

// data link headers
// 26 bytes = 208 bits without payload
struct ethHeader makeEthHeader(struct ipHeader ip, array<unsigned short, 3> srcMac, array<unsigned short, 3> destMac) {
    // header struct to return
    struct ethHeader eth;
    // 7 bytes = 56 bits
    fill(eth.preamble.begin(), eth.preamble.end(), 0);
    // 1 byte = 8 bits
    eth.SFD = 0;
    // 6 bytes = 48 bits
    eth.destMac = destMac;
    // 6 bytes = 48 bits
    eth.srcMac = srcMac;
    // 2 bytes = 16 bits
    eth.length = 64;
    // 46 - 1500 bytes, the data payload which is the ipHeaders
    eth.ipHeader = ip;
    // 4 bytes = 32 bytes
    eth.crc = 0;
    return eth;
};

// create the packet/frame
// fields that need to be correct: all addresses, 
// fields that arbitrary: checksum, payload, floaw label, 
struct ethHeader makePacket(bool tcp, unsigned short srcPort, unsigned short destPort, array<unsigned short, 8> srcIp, array<unsigned short, 8> destIp, array<unsigned short, 3> srcMac, array<unsigned short, 3> destMac){
    struct ipHeader ip;
    if (tcp){
        struct tcpHeader tcp = makeTcpHeader(srcPort, destPort);
        ip = makeIpHeader(tcp, srcIp, destIp);
    } else {
        struct udpHeader udp = makeUdpHeader(srcPort, destPort);
        ip = makeIpHeader(udp, srcIp, destIp);
    }
    struct ethHeader eth = makeEthHeader(ip, srcMac, destMac);
    return eth;
}

vector<MatchAction> makeTable(){
    array<unsigned short, 8> routerDestIp {2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008};
    array<unsigned short, 8> natSrcIp {2001, 2002, 2003, 2004, 2005, 2006, 2007, 9999};
    array<unsigned short, 8> firewallSrcIp {2001, 2002, 2003, 2004, 2005, 2006, 2007, 7777};
    array<unsigned short, 3> switchDestMac {1001, 2233, 4455};
    // this is to test the firewall
    unsigned short firewallSrcPort = 32;

    vector<MatchAction> matchActionTable = {
        // test for switch -- need to have mac, type, outputport
        {0, {}, {}, switchDestMac, SWITCH, 10},
        // test for router -- need to have ip, type, outputport
        {0, {}, routerDestIp, {}, ROUTER, 5},
        // test for NAT -- need to have ip, type
        {0, natSrcIp, {}, {}, NAT, 0},
        // test for firewall -- need to have ip, port num, type
        {firewallSrcPort, firewallSrcIp, {}, {}, FIREWALL, 0}
    };
    return matchActionTable;
}

int main (int argc, char* argv[]) {
    // create port nums, ip addrs, and mac addrs to pass into headers
    // for testing switch 
    array<unsigned short, 3> switchDestMac {1001, 2233, 4455};
    // for testing router
    array<unsigned short, 8> routerDestIp {2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008};
    // for testing NAT
    array<unsigned short, 8> natSrcIp {2001, 2002, 2003, 2004, 2005, 2006, 2007, 9999};
    // not going to use this to test but its here anyways
    array<unsigned short, 8> firewallIp {2001, 2002, 2003, 2004, 2005, 2006, 2007, 7777};
    // this is to test the firewall
    unsigned short firewallSrcPort = 32;

    array<unsigned short, 8> placeHolderIp {1111, 2002, 2003, 2004, 2005, 2006, 2007, 7777};
    array<unsigned short, 3> placeHolderMac {9999, 9999, 9999};

    // create the packets
    // packet to test switch
    struct ethHeader switchTestPacket = makePacket(true, 1, 0, placeHolderIp, placeHolderIp, {}, switchDestMac);
    // packet to test router
    struct ethHeader routerTestPacket = makePacket(true, 2, 0, placeHolderIp, routerDestIp, {}, placeHolderMac);
    // packet to test NAT box
    struct ethHeader natTestPacket = makePacket(true, 3, 0, natSrcIp, placeHolderIp, {}, placeHolderMac);
    // // packet to test firewall
    struct ethHeader firewallTestPacket = makePacket(true, firewallSrcPort, 0, placeHolderIp, placeHolderIp, {}, placeHolderMac);
    
    vector<MatchAction> matchTable = makeTable();
    // send to switch  
    // test the switch 
    checkForMatch(switchTestPacket, matchTable);
    // test the router
    checkForMatch(routerTestPacket, matchTable);
    // test the NAT box
    checkForMatch(natTestPacket, matchTable);
    // test the firewall
    checkForMatch(firewallTestPacket, matchTable);
}