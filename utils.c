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

void handle_packets(u_char* user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    printf("Packet arrived at %ld with data:\n", h->ts.tv_sec);
    for(int i=0; i<h->caplen; i++)
        printf("%x ", bytes[i]);
    printf("\n\n");
}