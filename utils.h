#pragma once
#include <stdbool.h>
#include <pcap/pcap.h>
#define DEBUG

#define NPCAP_ERROR printf("NPCAP error message: \"%s\"\n", errbuff);

static char errbuff[PCAP_ERRBUF_SIZE];
static const char* adapter_id = "\\Device\\NPF_{EE28EB53-E495-4860-BBC4-3E6F22BFA910}";

void print_availiable();
bool is_adapter_availiable(const char* adapter);
void handle_packets(u_char* user, const struct pcap_pkthdr *h, const u_char *bytes);
