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
    arp_header *arp_hdr = (arp_header *)packet; // casting input packet into arp header

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

    printf("\t\tSender MAC: %s\n", ether_ntoa((struct ether_addr *)arp_hdr->src_addr)); // sender MAC address
    memcpy(&ip_addr, arp_hdr->src_proto, 4); // moving source IP between buffers
    printf("\t\tSender IP: %s\n", inet_ntoa(ip_addr)); // displaying sender IP address
    printf("\t\tTarget MAC: %s\n", ether_ntoa((struct ether_addr *)arp_hdr->target_addr)); // target MAC address
    memcpy(&ip_addr, arp_hdr->target_proto, 4); // moving target IP between buffer
    printf("\t\tTarget IP: %s\n", inet_ntoa(ip_addr)); // displaying target IP address
    printf("\n");
}

void ip(const unsigned char *packet, int packet_len) {
    ip_header *ip_hdr = (ip_header *)packet; // casting input packet into ip header

    printf("\tIP Header\n");
    printf("\t\tIP PDU Len: %d\n", ntohs(ip_hdr->total_len));
    int header_len = (ip_hdr->version_and_ihl & 0x0F) * 4;
    printf("\t\tHeader Len (bytes): %d\n", header_len);
    printf("\t\tTTL: %d\n", ip_hdr->ttl);


    unsigned short cksumReturn = in_cksum((unsigned short *)ip_hdr, header_len);
    uint16_t checksum = ntohs(ip_hdr->header_checksum);
    unsigned int hc_high_byte = (checksum & 0xFF00);
    unsigned int hc_low_byte = (checksum & 0x00FF);

    struct in_addr ip_addr;

    if (ip_hdr->protocol == ICMP_PROTO) {
	printf("\t\tProtocol: ICMP\n");

    if (cksumReturn == 0) {
	    printf("\t\tChecksum: Correct (0x%02x%02x)\n", (hc_high_byte / 256), hc_low_byte);
    }
    else {
        printf("\t\tChecksum: Incorrect (0x%02x%02x)\n", (hc_high_byte / 256), hc_low_byte);
    }

	memcpy(&ip_addr, &ip_hdr->src_addr, 4);
    printf("\t\tSender IP: %s\n", inet_ntoa(ip_addr));
    memcpy(&ip_addr, &ip_hdr->dest_addr, 4);
   	printf("\t\tDest IP: %s\n", inet_ntoa(ip_addr));
    printf("\n");		

	icmp(packet + header_len, packet_len - header_len);
    } 
    else if (ip_hdr->protocol == TCP_PROTO) {
	printf("\t\tProtocol: TCP\n");

	if (cksumReturn == 0) {
    	printf("\t\tChecksum: Correct (0x%02x%02x)\n", (hc_high_byte / 256), hc_low_byte);
    }
    else {
        printf("\t\tChecksum: Incorrect (0x%02x%02x)\n", (hc_high_byte / 256), hc_low_byte);
    }

    memcpy(&ip_addr, &ip_hdr->src_addr, 4);
    printf("\t\tSender IP: %s\n", inet_ntoa(ip_addr));
    memcpy(&ip_addr, &ip_hdr->dest_addr, 4);
    printf("\t\tDest IP: %s\n", inet_ntoa(ip_addr));
    printf("\n");

	tcp(packet + header_len, packet_len - header_len, ip_hdr, header_len);
    }
    else if (ip_hdr->protocol == UDP_PROTO) {
    printf("\t\tProtocol: UDP\n");

	if (cksumReturn == 0) {
    	printf("\t\tChecksum: Correct (0x%02x%02x)\n", (hc_high_byte / 256), hc_low_byte);
    }
    else {
        printf("\t\tChecksum: Incorrect (0x%02x%02x)\n", (hc_high_byte / 256), hc_low_byte);
    }

    memcpy(&ip_addr, &ip_hdr->src_addr, 4);
    printf("\t\tSender IP: %s\n", inet_ntoa(ip_addr));
    memcpy(&ip_addr, &ip_hdr->dest_addr, 4);
    printf("\t\tDest IP: %s\n", inet_ntoa(ip_addr));
    printf("\n");

	udp(packet + header_len, packet_len - header_len, ip_hdr, header_len);
    }
    else {
	printf("\t\tProtocol: Unknown\n");
    }  	
}

void icmp(const unsigned char *packet, int packet_len) {
    icmp_header *icmp_hdr = (icmp_header *)packet; // casting input packet into icmp header

    printf("\tICMP Header\n");
    if (icmp_hdr->type == ICMP_REQ) {
	printf("\t\tType: Request\n");
    }
    else if (icmp_hdr->type == ICMP_REP) {
	printf("\t\tType: Reply\n");
    }
    else {
	printf("\t\tType: %d\n", icmp_hdr->type);
	printf("\n");
    }
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
    
