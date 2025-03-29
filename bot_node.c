#include <pcap/pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include "utils.h"


int main(int argc, char argv[])
{
    print_availiable();
    _Bool availiable = is_adapter_availiable(adapter_id);

    if(availiable)
        printf("%s is availiable\n", adapter_id);
    else
    {
        printf("%s is not availiable\n", adapter_id);
        return 1;
    }
    
    // 65536 - enough for a frame
    // promiscious to capture all packages, not only for us
    // 1000ms buffer timeout. That means that we will gather packets through this time and then analyze in portions 
    pcap_t* handler = pcap_open_live(adapter_id, 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, errbuff);

    if(!handler)
    {
        NPCAP_ERROR
        return 1;
    }

    pcap_loop(handler, 3, handle_packets, NULL);


    return 0;
}