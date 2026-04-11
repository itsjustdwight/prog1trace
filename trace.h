#ifndef TRACE_H
#define TRACE_H

#include <stdint.h>
#include <pcap.h>

#define ETHTYPE_IP 0x0800 // ether type hex for IPv4
#define ETHTYPE_ARP 0x0806 // ether type hex for ARP

/*ARP constants*/
#define ARP_REQ		1 // ARP Request constant; broadcasting for MAC
#define ARP_REP		2 // ARP Reply constant; unicast response providing MAC


