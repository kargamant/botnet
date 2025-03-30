#pragma once
#include <stdbool.h>
#include <pcap/pcap.h>
#define DEBUG

void print_availiable();
bool is_adapter_availiable(const char* adapter, pcap_if_t* device);
void handle_packets(u_char* user, const struct pcap_pkthdr *h, const u_char *bytes);
_Bool is_bot_command(const u_char *package);
void extract_attack_info(const u_char *packet, u_char *target_ip, u_char *attack_time);
void create_bot_command(const u_char target_ip[4], int attack_time, u_char* package);
void create_arp_attack(const u_char target_ip[4], const u_char sha[6], const u_char spa[4], u_char* package);
