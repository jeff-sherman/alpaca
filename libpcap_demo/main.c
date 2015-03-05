//
//  main.c
//  libpcap_demo
//
//  Created by Sherman, Jeffrey A. on 3/4/15.
//  Copyright (c) 2015 Sherman, Jeffrey A. All rights reserved.
//
//  Copying liberally from Tim Carsten's excellent demonstration:
//  http://www.tcpdump.org/sniffex.c
//
//  and the source of tcpdump-4.6.2. I think the latter is pretty spiffy, so
//  where appropriate I'm going to steal some of their argument syntax and
//  feature set.

/*
    WHAT:
    Quick and dirty packet capture demonstration using libpcap.
    
    Run with argument -h  to print usage information
    Run with argument -dd to print program parameters and exit.
 
    WHY:
    A tcpdump on a NIST timeserver for port 123 traffic yeilds ~1.6 GB of data
    per hour.
 
    We want... less. Maybe just a timestamped list of source IP addresses to 
    answer questions like:
        a) How many unique IP client addresses do we see over a month?
        b) What is the distribution of traffic over the work week, around DST
           transitions, leap second months, long weekends, etc. ?
        c) What is the distribution of very frequent/infrequent requesting IPs?
 
    WHO:
    Useful idiot, Jeff A. Sherman (jeff.sherman@nist.gov, x3511)
 
    HOW:
    We'll make the built-in packet filter and libpcap do the heavy lifting.
 
    We define a filter string for packets we are interested in, like "udp port 
    123", which libpcap_compile() turns into packet-filter byte code. The low-
    level packet filter code will then efficiently toss us matching packets for 
    processing.
 
    When we get a packet, we'll strip off the information we want to log and 
    throw away the rest. While the capture should happen with high process 
    priority (low pirority number), we can offload some of the data munging to
    a low priority process (high priority number).

    Because I envision running this program for long periods, let's set the 
    following aspirational design goals:
 
        1. At the earliest opportunity, i.e. after opening the packet capture, 
           we'll drop root privileges.
 
        2. Even if we're only logging 12 bytes per packet, logfiles may still 
           grow at a rate ~330 MB/hour (representative of time-a, for example). 
           So, we want to build in a mechanism for rotating logfiles and comp-
           ressing old log files automatically.
 
        3. Ideally, we should implement command line switches for termination 
           upon a certain number of captured packets, certain total run time, 
           etc. Safe builtin default values will be used if no command-line 
           arguments are given.
 
        4. I need to be CAREFUL because crashing the system is UNACCEPTABLE.
 
        5. This last goal is especially difficuly because this is my first 
           attempt at any of this stuff. So, I will attempt to hew closely to 
           modern C conventions and to steal very liberally from clear and 
           successful code like tcpdump.c.
 
    WHEN:
    Last significant documentation update: March 4, 2015 -jas.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/time.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>

/* Inlcude pwd.h and uuid.h to support dropping root privileges */
#include <pwd.h>
#include <uuid/uuid.h>

#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Default values for tunable parameters */

/* At 12 bytes, 1 billion packets is 12 GB uncompressed, which is about as much
   disk space as I'd ever want to use. We can consider raising this when the
   log rotation and compression scheme is proven.  Until then, this will limit
   the run time to about 1 day. 
 */

//#define DEFAULT_PACKET_COUNT_LIMIT  ((u_int64_t)1 << 30)      /* 1 073 741 824, or ~1.0 billion */
#define DEFAULT_PACKET_COUNT_LIMIT  10ULL                       /* Limit of 10 packets for quick tests */
#define MAX_PACKET_COUNT_LIMIT      ((u_int64_t)1 << 63) - 1    /* 9223372036854775807 or ~9.2e18 */

#define DEFAULT_SNAP_LEN            90
#define MAX_SNAP_LEN                1518

#define DEFAULT_LOG_ROTATE_SECONDS  60
#define MAX_LOG_ROTATE_SECONDS      3600

#define DEFAULT_NUMBER_LOG_FILES    1
#define MAX_NUMBER_LOG_FILES        336     /* 336 hours = 2 weeks */

#define DEFAULT_COMPRESS_MODE       0       /* Default no compression */
#define DEFAULT_OVERWRITE_MODE      0

#define DEFAULT_SAVEFILE_ROOT       "dumpfile"

/* Shamefully use some globals; set safe defaults where appropriate */
bool    debug = false;
pcap_t  *handle;                     /* Handle to libpcap capture process */
char    *username = NULL;            /* When dropping root, the user to adpot */

u_short snaplen = DEFAULT_SNAP_LEN;  /* Number of packet bytes to snarf */
u_int64_t packet_count_limit = DEFAULT_PACKET_COUNT_LIMIT;

time_t program_start_t;
time_t file_start_t;

u_int32_t capture_time_per_file = DEFAULT_LOG_ROTATE_SECONDS;
u_int32_t number_of_log_rotations = DEFAULT_NUMBER_LOG_FILES;
u_short compress_mode = DEFAULT_COMPRESS_MODE;
u_short overwrite_mode = DEFAULT_OVERWRITE_MODE;

char savefile_root[] = DEFAULT_SAVEFILE_ROOT;

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
    u_short udp_sport;              /* source port */
    u_short udp_dport;              /* destination port */
    u_short udp_len;                /* length */
    u_short udp_sum;                /* checksum */
};

static void print_usage(){
    
    fprintf(stderr, "------------------------80 character terminal template-------------------------\n");
    fprintf(stderr, "0        1         2         3        4         5         6         7         8\n");
    fprintf(stderr, "1234567890123456789012345678901234567801234567890123456789012345678901234567890\n");
    fprintf(stderr, "-------------------------------------------------------------------------------\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "     -c maxnum    quit after maxnum packets captured (default %llu, max %llu)\n",
            DEFAULT_PACKET_COUNT_LIMIT,MAX_PACKET_COUNT_LIMIT);
    fprintf(stderr, "     -d           turn debug messages on.\n");
    fprintf(stderr, "     -dd          print program parameters and exit.\n");
    fprintf(stderr, "     -h           display this help message. \n");
    fprintf(stderr, "     -s bytes     set packet snapshot length (default %d, max %d)\n",
            DEFAULT_SNAP_LEN,MAX_SNAP_LEN);
    fprintf(stderr, "     -G seconds   capture for defined time (default %d, max %d)\n",
            DEFAULT_LOG_ROTATE_SECONDS,MAX_LOG_ROTATE_SECONDS);
    fprintf(stderr, "     -W maxnum    quit after maxnum log file rotations (default %d, max %d)\n",
            DEFAULT_NUMBER_LOG_FILES,MAX_NUMBER_LOG_FILES);
    fprintf(stderr, "     -o           overwrite savefiles (default no, exit instead).\n");
    fprintf(stderr, "     -z           compress log files when rotated (default false).\n");
}

static void print_parameters(){
    /* Function called when -dd is passed in as an argument. */
    /* Print whatever parameters are set.  main() then exits. */
    
    fprintf(stderr, "------------------------80 character terminal template-------------------------\n");
    fprintf(stderr, "0        1         2         3        4         5         6         7         8\n");
    fprintf(stderr, "1234567890123456789012345678901234567801234567890123456789012345678901234567890\n");
    fprintf(stderr, "-------------------------------------------------------------------------------\n");
    fprintf(stderr, "-dd argument parsed. Printing program parameters and exiting...\n");
    fprintf(stderr, "Start time (seconds since epoch):       %ld\n",program_start_t);
    fprintf(stderr, "Savefile root:\n");
    fprintf(stderr, "Packet snapshot length (snaplen bytes): %d\n",snaplen);
    fprintf(stderr, "Capture time per log file (seconds):    %d\n",capture_time_per_file);
    fprintf(stderr, "Quit after capturing packets:           %llu\n",packet_count_limit);
    fprintf(stderr, "Quit after log file rotations:          %d\n",number_of_log_rotations);
    fprintf(stderr, "Compress log files on rotation:         %d\n",(compress_mode > 0));
    fprintf(stderr, "Overwrite log files instead of exiting: %d\n",(overwrite_mode > 0));
}

static void drop_root(const char *username){
    struct passwd *pw = NULL;
    
    if (!username) {
        fprintf(stderr,"Trying to drop root with no defined username. Exiting!\n");
        exit(EXIT_FAILURE);
    }
    
    pw = getpwnam(username);
    if (!pw) {
        fprintf(stderr,"Trying to drop root with unknown username %s. Exiting!\n", username);
        exit(EXIT_FAILURE);
    }
    
    /* If we're still here, username is valid; let's try to drop privileges. */
    if (initgroups(pw->pw_name, pw->pw_gid) != 0 ||
        setgid(pw->pw_gid) != 0 ||
        setuid(pw->pw_uid) != 0) {
        fprintf(stderr,"Couldn't drop root to '%.32s' uid=%lu gid=%lu: %s. Exiting!\n",
                username,
                (unsigned long)pw->pw_uid,
                (unsigned long)pw->pw_gid,
                pcap_strerror(errno));
        exit(EXIT_FAILURE);
    }
    else{
        if (debug) {
            fprintf(stderr,"Successfully dropped root to user '%s'.\n", username);
        }
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    static u_int64_t count = 0;                 /* packet counter */
    
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;      /* ethernet header */
    const struct sniff_ip *ip;                  /* ip header */
    const struct sniff_udp *udp;                /* udp header */
    
    int size_ip;
    //int size_udp;
    
    struct timeval ts;                          /* pcap timestamp */
    ts = header->ts;
    
    count++;
    ethernet = (struct sniff_ethernet *)packet;
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        fprintf(stderr,"Packet number %llu: invalid IP header length %u bytes.\n", count, size_ip);
        return;
    }
    
    if (ip->ip_p != IPPROTO_UDP) {
        fprintf(stderr,"Packet number %llu: not UDP. Protocol number is %u.\n", count, ip->ip_p);
        return;
    }
    
    udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
    if(debug){
        fprintf(stderr,"Packet number %llu at %ld.%d ", count, ts.tv_sec, ts.tv_usec);
        fprintf(stderr,"from src address %s port %u.\n", inet_ntoa(ip->ip_src), udp->udp_sport);
    }
    
    /* Check: is it time to stop capturing? */
    if (count >= packet_count_limit){
        pcap_breakloop(handle);
        if (debug) {
            fprintf(stderr,"Packet count %llu has reached limit; pcap_breakloop() called.\n",count);
        }
    }
}

// XCode's default main signature:
// int main(int argc, const char * argv[]) {

int main(int argc, char **argv){
    char *dev;                          /* device */
    char errbuf[PCAP_ERRBUF_SIZE];      /* error string placeholder */
    struct bpf_program fp;              /* compiled filter */
    char filter_exp[] = "udp port 123"; /* filter expression */
    bpf_u_int32 mask;                   /* our netmask */
    bpf_u_int32 net;                    /* out IP */
    
    register int cnt = 100000;          /* number to capture per loop-around */
    int loop_status = 0;                /* return of pcap_loop */
    bool finished = false;
    
    int op;                             /* command line argument */
    int dflag=0;
    
    /* On startup, get system time to seconds precision */
    program_start_t = time(NULL);
    if (program_start_t == (time_t)-1) {
        fprintf(stderr,"Error getting program start time. Exiting.\n");
        exit(EXIT_FAILURE);
    }
    
    /* Parse command line arguments */
    while((op = getopt(argc, argv, "dos:zh")) != -1){
        switch (op) {
            case 'd':
                dflag++;
                break;
            case 'o':
                overwrite_mode++;
                break;
            case 's':
                snaplen = atoi(optarg);
                if(snaplen > MAX_SNAP_LEN){
                    fprintf(stderr,"Restricting snaplen from %d to defined max %d.\n",snaplen,MAX_SNAP_LEN);
                    snaplen = MAX_SNAP_LEN;
                }
                break;
            case 'z':
                compress_mode++;
                break;
            case 'h':   /* drop through */
            case '?':   /* drop through */
            default:
                print_usage();
                exit(EXIT_SUCCESS);
                break;
        }
    }
    
    if (dflag >= 1) {
        debug = true;
        fprintf(stderr,"Debug messages on.\n");
    }
    if (dflag == 2) {
        /* Print what parameters are set and exit */
        print_parameters();
        exit(EXIT_SUCCESS);
    }
    
    
    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(EXIT_FAILURE);
    }
    
    /* Get device properties */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    
    /* Open session in non-promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }
    
    /* Verify we're capturing on an Ethernet device */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s is not an Ethernet.\n", dev);
        exit(EXIT_FAILURE);
    }
    
    /* Compile and apply the packet filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    
    /* Set the snapshot length */
    if (pcap_set_snaplen(handle, snaplen) == -1) {
        fprintf(stderr, "Couldn't set snapshot length to %d", snaplen);
        exit(EXIT_FAILURE);
    }
    
    /* Try dropping root */
    username = "shermanj";
    drop_root(username);
    
    /* Ok, launch the pcap_loop with our callback function defined */
    do{
        loop_status = pcap_loop(handle, cnt, got_packet, NULL);
    
        switch (loop_status) {
            case 0:
                finished = false;           /* cnt merely expired; let's go around again */
                break;
            case -1:
                finished = true;
                if (debug) {
                    fprintf(stderr,"pcap_loop exited with error status -1: %s.\n",pcap_geterr(handle));
                }
                break;
            case -2:
                finished = true;
                if (debug) {
                    fprintf(stderr,"pcap_loop exited with status -2 because pcap_breakloop() called.\n");
                }
                break;
            default:
                finished = true;
                fprintf(stderr,"pcap_loop exited with unexpected status %d; %s.\n",loop_status,pcap_geterr(handle));
                break;
        }
    } while(!finished);
        
    /* Clean up */
    pcap_freecode(&fp);
    pcap_close(handle);
    
    exit(EXIT_SUCCESS);
}
