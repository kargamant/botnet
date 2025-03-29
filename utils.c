#include "utils.h"
#include <pcap/pcap.h>
#include <string.h>

bool is_adapter_availiable(const char* adapter)
{
    pcap_if_t* node = malloc(sizeof(pcap_if_t));
    pcap_findalldevs(&node, NULL);

    #ifdef DEBUG
    printf("Devices:\n");
    #endif

    pcap_if_t* ptr = node;
    while(ptr)
    {
        #ifdef DEBUG
        printf("%s\n", ptr->name);
        #endif

        ptr = ptr->next;

        if(!strcmp(ptr->name, adapter))
        {
            pcap_freealldevs(node);
            return true;
        }    
    }

    pcap_freealldevs(node);
    return false;
}