/* trace.c */

#include "trace.h"
#include "checksum.h"

#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[])
{    
    if (argc != 2) { // checking if arguments == 2
	perror("Argument count must be 2");
	exit(1);
    }

    char *filename[] = argv[1]; // pcap file to be read
    char errbuf[PCAP_ERRBUF_SIZE]; // amount of chars in buffer

    struct pcap_pkthdr *header; // pre-defined header struct needed to access packet metadata
    const unsigned char *data; // pointer to actual bytes of packet data

    pcap_t *pcap_handle = pcap_open_offline(filename, errbuf) // opening pcap file

    int packetCounter = 0; // counter variable for # of packets in pcap
    while (int return = pcap_next_ex(pcap_handle, &p_header, &p_data) >= 0) {
	// printing current packet info
	printf("Packet number: %i Packet Len: %d", ++packetCounter, p_header->len);
    }
}
    
