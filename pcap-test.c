#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include "libnet.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_mac(const uint8_t* mac) {
	int i;
	for (i = 0; i < 5; i++) {
		printf("%02x:", mac[i]);
	}
	printf("%02x\n",mac[5]);
	return;
}

void print_ip(const struct in_addr ip) {
	char *str= inet_ntoa(ip);
	printf("%s\n", str);
	return;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

		struct libnet_ethernet_hdr* eth_hdr = packet;
		if(eth_hdr->ether_type != 0x0008) continue;
		struct libnet_ipv4_hdr* ip_hdr = eth_hdr+1;
			printf("Src MAC: "); 
			print_mac(eth_hdr->ether_shost);
			printf("Dst MAC: "); 
			print_mac(eth_hdr->ether_dhost);
			printf("Src IP: ");
			print_ip(ip_hdr->ip_src);
			printf("Dst IP: ");
			print_ip(ip_hdr->ip_dst);
	}

	pcap_close(pcap);
}
