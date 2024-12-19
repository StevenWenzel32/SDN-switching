#include <iostream>
#include <strings.h>      // bzero
#include <errno.h>        // errno
#include <string.h>       // for memset
#include "networkHeaders.hpp" // for the network header structs
#include <vector>
#include <string>
#include <functional>
#include <array>

using namespace std;

// get the dest mac addr - used for switch
array<unsigned short, 3> getDestMac(struct ethHeader eth){
    // parse/pass the ethernet header and get the dest mac addr
    return eth.destMac;
}

// get the dest IP addr - used for router
array<unsigned short, 8> getDestIp(struct ethHeader eth){
    // parse the ip header and get the dest ip addr
    return eth.ipHeader.destIp;
}

// get the src IP addr - used for NAT
array<unsigned short, 8> getSrcIp(struct ethHeader eth){
    // parse the ip header and get the src ip addr
    return eth.ipHeader.srcIp;
}

// get the src port num - for firewall 
unsigned short getSrcPort(struct ethHeader eth){
    // grab the type
    unsigned char type = eth.ipHeader.nextHeader;
    // check what type of transport header it is
    // tcp
    if (type == 6){
        // grab the port num from the transport header
        return eth.ipHeader.transportHeader.tcp.srcPort;
    } 
    // udp
    else if (type == 17){
        // grab the port num from the transport header
        return eth.ipHeader.transportHeader.udp.srcPort;
    } else {
        cerr << "Unknown Transport Header" << endl;
        return 0;
    }
}

// change the hop limit to one less
void updateHopLimit(struct ethHeader eth){
    // get the hop limit of the packet and decrement it
    eth.ipHeader.hopLimit--;
}

// print out the results of the matching, unused fields should be filled in with -1 -- need to change the params to the correct types?? ***
void printAction(enum FunctionType type, unsigned short srcPort, array<unsigned short, 3> destMac, array<unsigned short, 8> destIp, int outputPort, array<unsigned short, 8> srcIp, array<unsigned short, 8> newSrcIp){
    if (type == SWITCH){
        cout << "Packet with destination MAC ";
        for (int i = 0; i < destMac.size(); i++){
            cout << destMac[i];
            if (i != destMac.size() - 1){
                cout << ":";
            }
        }
        cout << " routed to port " << outputPort << endl;
    } else if (type == ROUTER){
        cout << "Packet with destination IP ";
        for (int i = 0; i < destIp.size(); i++){
            cout << destIp[i];
            if (i != destIp.size() - 1){
                cout << ":";
            }
        } 
        cout << " routed to port " << outputPort << endl;
    } else if (type == NAT){
        cout << "Packet headers rewritten. Original Source: ";
        for (int i = 0; i < srcIp.size(); i++){
            cout << srcIp[i];
            if (i != srcIp.size() - 1){
                cout << ":";
            }
        }
        cout << ", New Source: ";
        for (int i = 0; i < newSrcIp.size(); i++){
            cout << newSrcIp[i];
            if (i != newSrcIp.size() - 1){
                cout << ":";
            }
        }
        cout << endl;
    } else if (type == FIREWALL){
        cout << "Packet dropped because its from blocked port " << srcPort << endl; 
    } else {
        cout << "ERROR: bad action type in print action" << endl;
    }
}

// used for the NAT functionality -- changes the ip address to a hardcoded ip
void rewriteHeaders(struct ethHeader eth){
    // store the original dest and src
    array<unsigned short, 8> srcIp = eth.ipHeader.srcIp;
    array<unsigned short, 8> destIp = eth.ipHeader.destIp;
    // new src Ip to use
    array<unsigned short, 8> newSrcIp = {1111, 1111, 1111, 1111, 1111, 1111, 1111, 1111};

    // print results
    printAction(NAT, 0, {}, destIp, 0, srcIp, newSrcIp);
}

// checks the packet headers aganist the match + action table
// unsure how to setup the table -- will porbably use multiple tables
    // a table/list for macs->ports, ips->ports/drops/rewrite
void checkForMatch(struct ethHeader eth, vector<MatchAction> matchActionTable){
    // get the dest mac address
    array<unsigned short, 3> destMac;
    destMac = getDestMac(eth);
    // get the dest ip address
    array<unsigned short, 8> destIp;
    destIp = getDestIp(eth);
    // get the dest ip address
    array<unsigned short, 8> srcIp;
    srcIp = getSrcIp(eth);
    // for the firewall
    unsigned short srcPort = getSrcPort(eth);

    for (int i = 0; i < matchActionTable.size(); i++)
    {
        // Switch: output based on Mac addr
        if (destMac == matchActionTable[i].destMac){
            // reduce the hop limit
            updateHopLimit(eth);
            // print out mac addr and the output port
            printAction(SWITCH, 0, destMac, {}, matchActionTable[i].outputPort, {}, {});
            return;
        }
        // Router: output based on ip addr
        else if (destIp == matchActionTable[i].destIp){
            // reduce the hop limit
            updateHopLimit(eth);
            // print out ip addr and the output port
            printAction(ROUTER, 0, {}, destIp, matchActionTable[i].outputPort, {}, {});
            return;
        }
        // NAT: rewrite headers based on some ip addr
        else if (srcIp == matchActionTable[i].srcIp){
            // print out the originals and the changed of the headers that were changed
            rewriteHeaders(eth);
            return;
        }
        // firewall: drop packets on port X to certain ip addrs Y
        else if (srcPort == matchActionTable[i].srcPort){
            // not using this right now for a simpler design
            //if (destIp == ipAddrsY){
                // print out why the packet was dropped
                printAction(FIREWALL, srcPort, {}, {}, 0, {}, {});
                return;
            //}
        }
    }
    // if nothing is found in the loop then do the default action
    printAction(ROUTER, 0, {}, destIp, 55, {}, {});
}