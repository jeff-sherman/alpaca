//
//  alpaca-ethernet.h
//  alpaca
//
//  Created by Sherman, Jeffrey A. on 3/11/15.
//  Copyright (c) 2015 Sherman, Jeffrey A. All rights reserved.
//

#ifndef alpaca_alpaca_ethernet_h
#define alpaca_alpaca_ethernet_h

#define SIZE_ETHERNET       14      /* Ethernet header is always 14 bytes */
#define ETHER_ADDR_LEN      6       /* Ethernet HW address is always 6 bytes */
struct sniff_ethernet{
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;             /* IP? ARP? Etc. */
};

struct sniff_ip{
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* Type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF   0x8000              /* reserved fragment flag */
#define IP_DF   0x4000              /* don't fragment flag */
#define IP_MF   0x2000              /* more fragments flag */
#define IP_OFFMASK 0x1fff           /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct in_addr ip_src, ip_dst;  /* source and destination IP addresses */
};
#define IP_HL(ip)   (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)    (((ip)->ip_vhl) >> 4)

struct sniff_udp{
    u_int16_t udp_sport;              /* source port */
    u_int16_t udp_dport;              /* destination port */
    u_int16_t udp_len;                /* length */
    u_int16_t udp_sum;                /* checksum */
};


#endif
