/* trace.h */

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

/* ICMP constants */
#define ICMP_REQ	8 // ICMP Request constant
#define ICMP_REP	0 // ICMP Reply constant

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
} __attribute__((packed)) ethernet_header;

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
} __attribute__((packed)) arp_header;

/* IP header */
typedef struct
{
    uint8_t version_and_ihl; // version and ip header length
    uint8_t tos; // type of service
    uint16_t total_len; // total length of IP header
    uint16_t identification; // identity of fragments in IP datagram
    uint16_t flag_and_frag_offset; // flags and fragment offset
    uint8_t ttl; // time to live for the datagram; prevents network loopins by restricting hops
    uint8_t protocol; // name of protocol to which the data is passed 
    uint16_t header_checksum; // error checking datagram header
    uint32_t src_addr; // source IP address
    uint32_t dest_addr; // destination IP address
} __attribute__((packed)) ip_header;

/* ICMP header */
typedef struct
{
    uint8_t type; // descriibes type of the message so receiving network knows
    uint8_t code; // carries information abour error message and type
    uint16_t checksum; // checks number of bits of message to ensure complete data is delievred
} __attribute__((packed)) icmp_header;

/* UDP header */
typedef struct
{
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed)) udp_header;

/* TCP header */
typedef struct
{
    uint16_t src_port; // identifies port number of app sending the data
    uint16_t dest_port; // identifies port number of app receiving the data
    uint32_t sequence_number; // indicates the position of 1st byte in this segment, assuring data can be reassembled
    uint32_t ack_number; // confirms successful receipt of data; indicates next byte sender should transmit
    uint8_t data_offset_and_reserved; // shows where data begins in packet
    uint8_t flags; // CWR; ECE; URG; ACK; PSH; RST; SYN; FIN
    uint16_t window; // determines amount of data receiver can accept; provides flow control
    uint16_t checksum; // detects erros in header and data
    uint16_t urgent_pointer; // points to urgent data that should be immediately processed
} __attribute__((packed)) tcp_header;

/* Pseudo-header for TCP/UDP checksum */
typedef struct
{
    uint32_t src_addr; // source IP address of maker of datagram, from IP header
    uint32_t dest_addr; // destination IP address of maker of datagram, from IP header
    uint8_t reserved; // 8 bits of zeros
    uint8_t protocol; // protocol from the IP header
    uint16_t TCP_segment_length; // length of TCP segment, including header and data
} __attribute__((packed)) pseudo_header;

/*-----------> Function Prototypes <-----------*/

/* Required parser functions */
void ethernet(const unsigned char *packet, int packet_len);
void arp(const unsigned char *packet, int packet_len);
void ip(const unsigned char *packet, int packet_len);
void icmp(const unsigned char *packet, int packet_len);
void tcp(const unsigned char *packet, int packet_len, 
	 const ip_header *ip_hdr, int ip_header_len);
void udp(const unsigned char *packet, int packet_len,
	 const ip_header *ip_hdr, int ip_header_len);

#endif
