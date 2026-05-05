#include<stdint.h>
#include<arpa/inet.h>

typedef struct ethernet_header {
    uint8_t dst_MAC [6];
    uint8_t src_MAC [6];
    uint16_t ethernet_type;
} ethernet_header;

typedef struct ipv4_header {
    uint8_t version_ihl;//4bits
    uint8_t tos;
    uint16_t total_len;
    uint16_t identification;
    uint16_t flags_fragment_offset; //3,13bits
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
} ipv4_header;

typedef struct __attribute__((packed)) ipv6_header {
    uint8_t version;//4bits
    uint8_t traffic_class;//8bits
    uint32_t flowlabel;//20bits
    uint16_t payload_len;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src_ip6 [16];
    uint8_t dst_ip6 [16];
} ipv6_header; 

typedef struct __attribute__((packed)) tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence_num;
    uint32_t ack_num;
    uint16_t dataoffset_reversed_flags;//4,3,9bits
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
} tcp_header; 

typedef struct tcp_ipv4{
    ethernet_header eth;
    ipv4_header ipv4;
    tcp_header tcp;
} tcp_ipv4;

typedef struct tcp_ipv6{
    ethernet_header eth;
    ipv6_header ipv6;
    tcp_header tcp;
} tcp_ipv6;