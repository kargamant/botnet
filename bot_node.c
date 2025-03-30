#include <pcap/pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include "utils.h"
#include <stdint.h>
#include <pcap/socket.h>
#include <ntddndis.h>

// errbuff for npcap error messages
extern char errbuff[PCAP_ERRBUF_SIZE];
#define NPCAP_ERROR printf("NPCAP error message: \"%s\"\n", errbuff);

extern char* adapter_id;

extern u_char bot_node_mac[6];
extern u_char bot_node_ip[4];

int main(int argc, char* argv[])
{
    // op1 - adapter name to listen to
    if(argc<=1)
    {
        printf("Error. No adapter name specified.\n");
        return 1;
    }
    else
    {
        adapter_id = argv[1];
    }

    printf("adapter_id: %s\n", adapter_id);

    print_availiable();
    pcap_if_t device;
    _Bool availiable = is_adapter_availiable(adapter_id, &device);
    
    if(availiable)
    printf("%s is availiable\n\n", adapter_id);
    else
    {
        printf("%s is not availiable\n\n", adapter_id);
        return 1;
    }

    struct pcap_addr* ptr = device.addresses;
    
    while(ptr)
    {
        if(ptr->addr)
        {
            uint32_t ip = ((struct sockaddr_in *)ptr->addr)->sin_addr.s_addr;
            for(int i=0; i<4; i++)
                bot_node_ip[i] = *((u_char*)(&ip)+i);
            break;
        }
        ptr = ptr->next;
    }

    #ifdef DEBUG
    ptr = device.addresses;
    while(ptr)
    {
        if(ptr->addr)
        {
            printf("addr: ");
            uint32_t ip = ((struct sockaddr_in *)ptr->addr)->sin_addr.s_addr;
            for(int i=0; i<3; i++)
                printf("%d.", *((u_char*)(&ip)+i));
            printf("%d\n", *((u_char*)(&ip)+3));
        }
        if(ptr->netmask)
        {
            printf("netmask: ");
            uint32_t netmask = ((struct sockaddr_in *)ptr->netmask)->sin_addr.s_addr;
            for(int i=0; i<3; i++)
                printf("%d.", *((u_char*)(&netmask)+i));
            printf("%d\n", *((u_char*)(&netmask)+3));
        }
        if(ptr->broadaddr)
        {
            printf("broadaddr: ");
            uint32_t broadaddr = ((struct sockaddr_in *)ptr->broadaddr)->sin_addr.s_addr;
            for(int i=0; i<3; i++)
                printf("%d.", *((u_char*)(&broadaddr)+i));
            printf("%d\n", *((u_char*)(&broadaddr)+3));
        }
        if(ptr->dstaddr)
        {
            printf("dstaddr: %d\n", ptr->dstaddr->sa_data[0]);
        }
        
        ptr = ptr->next;
    }
    #endif

    #ifdef DEBUG
    printf("IP: ");
    for(int i=0; i<3; i++)
            printf("%d.", bot_node_ip[i]);
    printf("%d\n\n", bot_node_ip[3]);
    #endif
    
    // 65536 - enough for a frame
    // promiscious to capture all packages, not only for us
    // 1000ms buffer timeout. That means that we will gather packets through this time and then analyze in portions 
    pcap_t* handler = pcap_open_live(device.name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, errbuff);

    if(!handler)
    {
        NPCAP_ERROR
        return 1;
    }

    size_t len = 6;
    pcap_oid_get_request(handler, OID_802_3_CURRENT_ADDRESS, bot_node_mac, &len);

    #ifdef DEBUG
    printf("MAC: ");
    for(int i=0; i<6; i++)
        printf("%x:", bot_node_mac[i]);
    printf("\n\n");
    #endif

    printf("Listening to bot_master command:\n");

    // very VERY brave move, it works, but passing handler this way(as user pointer) is EXTREMELY UNSAFE!
    pcap_loop(handler, 0, handle_packets, (u_char*)handler);


    return 0;
}