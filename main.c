#include <pcap.h>
#include <stdio.h>

#define ETHR_ADDR_LEN 6

struct ethernet_hdr
{
    uint8_t  ether_dhost[ETHER_ADDR_LEN];   /* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];   /* source ethernet address */
    uint16_t ether_type;                    /* protocol */
};

typedef struct
{
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

void usage()
{
    printf("Syntax: send-packet <interface> <src MAC Addr> <dest MAC Addr>\n");
    printf("Sample: send-packet wlan1 AA:BB:CC:DD:EE:FF AA:BB:CC:DD:EE:FF");
}

// Parsing arguments
bool parse(Param* param, int argc, char* argv[])
{
    if(argc != 4)
    {
        usage();
        return false;
    }
    param->dev_ argv[1];
    return true;
}

int main(int argc, char *argv[])
{
}