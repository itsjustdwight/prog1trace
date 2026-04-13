/* trace.c */

#include "trace.h"
#include "checksum.h"

#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[])
{
    
    if (argc != 2) {
	perror("Argument count must be 2");
	exit(1);
    }

    pcap_t *pcap_handle = pcap_open_offline(filename, errbuf) // opening pcap file

    int packetCounter = 0; // counter variable for # of packets in pcap
    while (int return = pcap_next_ex(pcap_handle, &header, &data) >= 0) {
    }
    
