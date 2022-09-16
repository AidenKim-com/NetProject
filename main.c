#include <pcap.h>
#include <stdio.h>

#define MAC_ADDR_LEN 6



struct ethernet_hdr
{
    uint8_t  ether_dhost[MAC_ADDR_LEN];   /* destination ethernet address */
    uint8_t  ether_shost[MAC_ADDR_LEN];   /* source ethernet address */
    uint16_t ether_type;                    /* protocol */
};

/*
    Radiotap Header
*/
struct radiotap_hdr
{
    u_char hdr_rev;     // Header revision
    u_char hdr_pad;     // Header Header pad
    u_short hdr_len;    // Header length
}


/*
    802.11 Authentication Header
*/
struct wlan_auth_hdr
{
    u_short frame_control;              // Frame Control
    u_short duration_ID;                // Duration ID
    uint8_t mac_dhost[MAC_ADDR_LEN];    // Destination MAC Addr
    uint8_t mac_shost[MAC_ADDR_LEN];    // Source MAC Addr
    uint8_t bss_id[MAC_ADDR_LEN];       // BSS ID MAC Addr
    u_short sequence_control;           // Sequence Control 
    
};

/*
    802.11 Authentication Body
*/
struct wlan_auth_body
{
    u_short auth_algorithm_num;         // Authentication Algorithm Number
    u_short auth_seq;                   // Authentication Transaction Sequence
    u_short status_code;                // Status Code
    // Variable Challenge Text
};

/*
    802.11 Authentication Frame
*/
struct wlan_auth_frame
{
    struct wlan_auth_hdr auth_hdr;
    struct wlan_auth_body auth_body;
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