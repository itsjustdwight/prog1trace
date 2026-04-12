#ifndef TRACE_H
#define TRACE_H

/*-----------> Includes/Constants <-----------*/

#include <stdint.h>
#include <pcap.h>

#define ETHTYPE_IP 0x0800 // ether type hex for IPv4
#define ETHTYPE_ARP 0x0806 // ether type hex for ARP

/*ARP constants*/
#define ARP_REQ		1 // ARP Request constant; broadcasting for MAC
#define ARP_REP		2 // ARP Reply constant; unicast response providing MAC

/* IP Protocol constants */
#define ICMP_PROTO	1 // ICMP protocol number
#define TCP_PROTO	6 // TCP protocol number
#define UDP_PROTO	17 // UDP protocol number

/* Service ports and numbers */
#define FTP_PORT	21 // FTP port number; file transfer
#define TELNET_PORT	23 // TELNET port number; unencrypted text comms
#define SMTP_PORT	25 // SMTP port number; email routing between mail servers
#define DNS_PORT	53 // DNS port number; domain name sys. name resolver
#define HTTP_PORT	80 // HTTP port number; transport protocol on top of UDP
#define POP3_PORT	110 // POP3 port number; post office protocol

/*-----------> Structs <-----------*/

/* Ethernet header */
typedef struct
{
    uint8_t dest_addr[6]; // destination MAC address
    uint8_t src_addr[6]; // source MAC address
    uint16_t ethertype; // type pointing to payload
} __attribute__((packed)) ethernet_header_t;

/* ARP header */
typedef struct
{
    uint16_t hardware_type; // type of network ARP is running
    uint16_t protocol_type; // defining protocol
    uint8_t hardware_addr_len; // length of physical address
    uint8_t protocol_addr_len; // length of logical address
    uint16_t operation; // defining type of packet (operation done)
    uint8_t src_addr[6]; // physical addr. of sender (variable length)
    uint8_t src_proto[4]; // logical addr. of sender (variable length)
    uint8_t target_addr[6]; // physical addr. of target (variable length)
    uint8_t target_proto[4]; // logical addr. of target (variable length)
} __attribute__((packed)) arp_header_t;

/*-----------> Function Prototypes <-----------*/

/* Required parser functions */
void parse_ethernet(const unsigned char *packet, int packet_len);
void parse_ethernet(const unsigned char *packet, int packet_len);
void parse_ip(const unsigned char *packet, int packet_len);
void parse_icmp(const unsigned char *packet, int packet_len);
void parse_tcp(const unsigned char *packet, int packet_len
	       const ip_header_t *ip_hdr, int ip_header_len);
void parse_udp(const unsigned char *packet, int packet_len);
