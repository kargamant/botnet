#include "utils.h"
#include <pcap/pcap.h>
#include <string.h>
#include <stdlib.h>



_Bool is_adapter_availiable(const char* adapter)
{
    pcap_if_t* node = NULL;
    char* buff = malloc(PCAP_ERRBUF_SIZE);

    char code = pcap_findalldevs(&node, buff);

    if(code)
    {
        printf("NPCAP error message: \"%s\"\n", buff);
        free(buff);
        return false;
    }

    free(buff);
        
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
    char* buff = malloc(PCAP_ERRBUF_SIZE);

    char code = pcap_findalldevs(&node, buff);

    if(code)
    {
        printf("NPCAP error message: \"%s\"\n", buff);
        free(buff);
        return;
    }

    free(buff);

    printf("Devices availiable:\n");

    pcap_if_t* ptr = node;
    while(ptr)
    {
        printf("%s (%s)\n", ptr->name, ptr->description ? ptr->description : "no_description");
        
        ptr = ptr->next;
    }

    pcap_freealldevs(node);
}