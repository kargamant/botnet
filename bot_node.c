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
        printf("%s is not availiable\n", adapter_id);
    
    return 0;
}