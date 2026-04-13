/* trace.c */

#include "trace.h"
#include "checksum.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

/*-----------> Parsing Functions <-----------*/
void ethernet(const unsigned char *packet, int packet_len) {
    ethernet_header *eth_header = (ethernet_header *)packet; // casting input packet into ethernet header
    
    printf("\tEthernet Header\n");
    printf("\t\tDest MAC: %s\n", ether_ntoa((struct ether_addr *)eth_header->dest_addr));
    printf("\t\tSource MAC: %s\n", ether_ntoa((struct ether_addr *)eth_header->src_addr));

    if (ntohs(eth_header->ethertype) == ETHTYPE_ARP) { // checking which type is in eth header
	printf("\t\tType: ARP\n"); // ARP ethertype
	printf("\n");
	arp(packet + 14, packet_len - 14);
    } 
    else if (ntohs(eth_header->ethertype) == ETHTYPE_IP) {
	printf("\t\tType: IP\n"); // IP ethertype
	printf("\n");
	ip(packet + 14, packet_len - 14);
    } 
    else {
	printf("\t\tType: Undefined\n\n"); // for debugging
	printf("\n");
    }  
}

void arp(const unsigned char *packet, int packet_len) {
    arp_header *arp_hdr = (arp_header *)packet; // casting input packet into ethernet header

    printf("\tARP header\n");

    if (ntohs(arp_hdr->operation) == ARP_REQ) {
	printf("\t\tOpcode: Request\n"); // request operation
    }
    else if (ntohs(arp_hdr->operation) == ARP_REP) {
	printf("\t\tOpcode: Reply\n"); // reply operation
    }
    else {
	printf("\t\tOpcode: Operation not supported\n"); // for debugging
    }

    struct in_addr ip_addr;

    printf("\t\tSender MAC: %s\n", ether_ntoa((struct ether_addr *)arp_hdr->src_addr));
    memcpy(&ip_addr, arp_hdr->src_proto, 4);
    printf("\t\tSender IP: %s\n", inet_ntoa(ip_addr));
    printf("\t\tTarget MAC: %s\n", ether_ntoa((struct ether_addr *)arp_hdr->target_addr));
    memcpy(&ip_addr, arp_hdr->target_proto, 4);
    printf("\t\tTarget IP: %s\n", inet_ntoa(ip_addr));
    printf("\n");
}

void ip(const unsigned char *packet, int packet_len) {
	// TODO: implement
}

void icmp(const unsigned char *packet, int packet_len) {
	// TODO: implement
}

void tcp(const unsigned char *packet, int packet_len,
	 const ip_header *ip_hdr, int ip_header_len) {
	// TODO: implement
}

void udp(const unsigned char *packet, int packet_len,
	 const ip_header *ip_hdr, int ip_header_len) {
	// TODO: implement
}


/*-----------> Main <-----------*/
int main(int argc, char *argv[])
{    
    if (argc != 2) { // checking if arguments == 2
	perror("Argument count must be 2");
	exit(1);
    }

    char *filename = argv[1]; // pcap file to be read
    char errbuf[PCAP_ERRBUF_SIZE]; // amount of chars in buffer

    struct pcap_pkthdr *p_header; // pre-defined header struct needed to access packet metadata
    const unsigned char *p_data; // pointer to actual bytes of packet data

    pcap_t *pcap_handle = pcap_open_offline(filename, errbuf); // opening pcap file
    if (pcap_handle == NULL) {
	fprintf(stderr, "Error: %s\n", errbuf);
	exit(1);
    }

    int packetCounter = 0; // counter variable for # of packets in pcap
    int result; // return value from iterating through pcap file
    while ((result = pcap_next_ex(pcap_handle, &p_header, &p_data)) == 1) {
	// printing current packet info
	printf("\nPacket number: %i  Packet Len: %d\n\n", ++packetCounter, p_header->len);
    
	ethernet(p_data, p_header->len);
    }

    pcap_close(pcap_handle); // closing pcap file that was opened
    return 0; // satisfying int return value
}
    
