#include "utils.h"
#include <pcap/pcap.h>
#include <string.h>
#include <stdlib.h>



bool is_adapter_availiable(const char* adapter)
{
    pcap_if_t* node = malloc(sizeof(pcap_if_t));
    char* buff = malloc(sizeof(1000));
    
    pcap_findalldevs(&node, buff);

    printf("%s\n", buff);
    free(buff);

    #ifdef DEBUG
    printf("Devices iterated:\n");
    #endif

    pcap_if_t* ptr = node;
    while(ptr)
    {

        #ifdef DEBUG
        printf("%s\n", ptr->name);
        #endif

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