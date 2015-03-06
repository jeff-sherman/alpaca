//
//  alpaca.c
//  alpaca - "ALways PAcket CApturing"
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
 
    We intend to run it for long periods, hence the name:
    alpaca - "ALways PAcket CApturing"
           - "A Lightweight PAcket CApture"
           - "
    
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
    The built-in packet filter and libpcap will do the heavy lifting.
 
    We define a filter string for packets we are interested in, like "udp port 
    123", which libpcap_compile() turns into packet-filter byte code. The low-
    level packet filter code then efficiently tosses us matching packets for
    further processing.
 
    When we get a packet, we'll log what little information we want and throw
    away the rest. While the capture should happen with high process priority
    (low pirority number), we can offload some of the data munging to a low
    priority process (high priority number).

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
 
        4. I need to be CAREFUL because crashing a live system is UNACCEPTABLE.
 
        5. This last goal is especially difficult because this is my first
           attempt at any of this stuff. So, I will attempt to hew closely to 
           modern C conventions and to steal very liberally from clear and 
           successful code like tcpdump. I might even learn what I'm doing
           along the way.
 
    For now the output file format will be flexible. Suggest extenstion:
    ".spit" for Special Packet Information Tally.
 
    WHEN:
    Last significant documentation update: March 5, 2015 -jas.
*/

#define APP_NAME                    "alpaca"
#define APP_FILE_EXTENSION          "spit"
#define APP_VERSION_MAJOR           0
#define APP_VERSION_MINOR           1

#define MAC_OS_X

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/cdefs.h>
#include <stdbool.h>
#include <strings.h>
#include <sys/time.h>
#include <errno.h>
#include <getopt.h>

/* Inlcude pwd.h and uuid.h to support dropping root privileges */
#include <pwd.h>
#include <uuid/uuid.h>

/* Include pcap and some networking libraries */
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Default values for tunable parameters */

/* At 12 bytes, 1 billion packets is 12 GB uncompressed, which is about as much
   disk space as I'd ever want to use. We can consider raising this when the
   log rotation and compression scheme is proven. Until then, a 1 billion limit
   on packet count will limit us to about a day of runtime.
 */

//#define DEFAULT_PACKET_COUNT_LIMIT  ((u_int64_t)1 << 30)      /* 1 073 741 824, or ~1.0 billion */
#define DEFAULT_PACKET_COUNT_LIMIT  1000ULL                     /* Limit of 1000 packets for quick tests */
#define MAX_PACKET_COUNT_LIMIT      ((u_int64_t)1 << 63) - 1    /* 9223372036854775807 or ~9.2e18 */

#define DEFAULT_SNAP_LEN            90
#define MAX_SNAP_LEN                1518

#define DEFAULT_LOG_ROTATE_SECONDS  30
#define MAX_LOG_ROTATE_SECONDS      3600

#define DEFAULT_NUMBER_LOG_FILES    3
#define MAX_NUMBER_LOG_FILES        336     /* 336 hours = 2 weeks */

#define DEFAULT_COMPRESS_MODE       0       /* Default no compression */
#define DEFAULT_OVERWRITE_MODE      0

#define DEFAULT_DUMPFILE_ROOT       "alpaca_out"
#ifndef PATH_MAX
#define PATH_MAX                    1024
#endif

/* XCode seems to have brain damage; it doesn't set the working directory
   correctly when debugging the process as root.  So, during development
   we'll keep this nonsense around. */
#ifdef  MAC_OS_X
#define DEFAULT_PATH_FROM_CWD   "/Users/shermanj/"
#else
#define DEFAULT_PATH_FROM_CWD   ""
#endif


/* Shamefully use some globals; set safe defaults where appropriate */
bool    debug = false;
pcap_t  *handle;                     /* Handle to libpcap capture process */
char    *username = NULL;            /* When dropping root, the user to adpot */

u_short   limit_snaplen         = DEFAULT_SNAP_LEN;
u_int64_t limit_packet_count    = DEFAULT_PACKET_COUNT_LIMIT;
u_int32_t limit_time_per_file   = DEFAULT_LOG_ROTATE_SECONDS;
u_int32_t limit_log_rotations   = DEFAULT_NUMBER_LOG_FILES;

u_short   compress_mode         = DEFAULT_COMPRESS_MODE;
u_short   overwrite_mode        = DEFAULT_OVERWRITE_MODE;

time_t    program_start_t;
time_t    file_start_t;
int       file_count = 0;
char      dumpfile_dirpath[]    = DEFAULT_PATH_FROM_CWD;
char      dumpfile_root[]       = DEFAULT_DUMPFILE_ROOT;
char      current_file_name[PATH_MAX];
FILE      *fd;

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

/*
struct dump_info_t {
    char    *root_file_name;
    char    *current_file_name[PATH_MAX];
    pcap_t  *pd;
    FILE    *fd;
};
*/

static void print_usage(){
    
    fprintf(stdout, "------------------------80 character terminal template-------------------------\n");
    fprintf(stdout, "0        1         2         3        4         5         6         7         8\n");
    fprintf(stdout, "1234567890123456789012345678901234567801234567890123456789012345678901234567890\n");
    fprintf(stdout, "-------------------------------------------------------------------------------\n");
    fprintf(stdout, "Usage: %s -[cdhoz] [-s bytes] [-G seconds] -[W maxnum] \n",APP_NAME);
    fprintf(stdout, "     -c maxnum    quit after maxnum packets captured (default %llu, max %llu)\n",
            DEFAULT_PACKET_COUNT_LIMIT,MAX_PACKET_COUNT_LIMIT);
    fprintf(stdout, "     -d           turn debug messages on.\n");
    fprintf(stdout, "     -dd          print program parameters and exit.\n");
    fprintf(stdout, "     -h           display this help message. \n");
    fprintf(stdout, "     -s bytes     set packet snapshot length (default %d, max %d)\n",
            DEFAULT_SNAP_LEN,MAX_SNAP_LEN);
    fprintf(stdout, "     -G seconds   capture for defined time (default %d, max %d)\n",
            DEFAULT_LOG_ROTATE_SECONDS,MAX_LOG_ROTATE_SECONDS);
    fprintf(stdout, "     -W maxnum    quit after maxnum log file rotations (default %d, max %d)\n",
            DEFAULT_NUMBER_LOG_FILES,MAX_NUMBER_LOG_FILES);
    fprintf(stdout, "     -o           overwrite savefiles (default no, exit instead).\n");
    fprintf(stdout, "     -z           compress log files when rotated (default false).\n");
}

static void print_parameters(){
    /* Function called when -dd is passed in as an argument. */
    /* Print whatever parameters are set.  main() then exits. */
    
    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));
    
    fprintf(stdout, "------------------------80 character terminal template-------------------------\n");
    fprintf(stdout, "0        1         2         3        4         5         6         7         8\n");
    fprintf(stdout, "1234567890123456789012345678901234567801234567890123456789012345678901234567890\n");
    fprintf(stdout, "-------------------------------------------------------------------------------\n");
    fprintf(stdout, "-dd argument parsed. Printing program parameters and exiting...\n");
    fprintf(stdout, "Start time (seconds since epoch):       %ld\n",program_start_t);
    fprintf(stdout, "Dumpfile root filename:                 %s\n",dumpfile_root);
    fprintf(stdout, "Packet snapshot length (snaplen bytes): %d\n",limit_snaplen);
    fprintf(stdout, "Capture time per log file (seconds):    %d\n",limit_time_per_file);
    fprintf(stdout, "Quit after capturing packets:           %llu\n",limit_packet_count);
    fprintf(stdout, "Quit after log file rotations:          %d\n",limit_log_rotations);
    fprintf(stdout, "Compress log files on rotation:         %d\n",(compress_mode > 0));
    fprintf(stdout, "Overwrite log files instead of exiting: %d\n",(overwrite_mode > 0));
    fprintf(stdout, "Current working directory: %s\n",cwd);
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
            fprintf(stderr,"Successfully dropped from root to user '%s'.\n", username);
        }
    }
}

static void compose_dumpfile_name(int cnt, int max_chars){
    char *buffer = malloc(PATH_MAX+1);
    
    if (cnt == 0 && max_chars == 0) {
        if (sprintf(buffer, "%s%s.%s", dumpfile_dirpath, dumpfile_root,APP_FILE_EXTENSION) > PATH_MAX){
            fprintf(stderr, "Error composing a filename with too many characters.  Exiting.\n");
            exit(EXIT_FAILURE);
        }
    }
    else{
        if (sprintf(buffer, "%s%s%0*d.%s", dumpfile_dirpath, dumpfile_root, max_chars,cnt,APP_FILE_EXTENSION) > PATH_MAX){
            fprintf(stderr, "Error composing a filename with too many characters.  Exiting.\n");
            exit(EXIT_FAILURE);
        }
    }
    strcpy(current_file_name,buffer);
    free(buffer);
}

#define ALPACA_WORD     4
#define ALPACA_TERM     0xFFFFFFFF

void alpaca_spit(register FILE *fd, const time_t ts, const struct in_addr a){

    /* Notes about byte ordering:
     So, timestamps (type long) are written in little-endian, at least on my
     Mac.  So, for example:
     ts = 1 425 664 608 is saved as 0x60 0xEA 0xF9 0x54
     
     Meanwhile, IPv4 addresses are probably stored in network byte order,
     which I guess is big-endian. So, for example,
     a = 132.163.11.126 is saved as 0x84 0xA3 0x0B 0x7E
     
     This is pretty goofy, and maybe I'll do something about it later, but
     not now.
     
     Notes about a file format.
     
     With the aim towards maximum compression, here's my clever idea. The first
     word we write in a file is the integer second timestamp, followed by an
     IPv4 address. Then, as long as the timestamp doesn't roll-over to the next
     second, we just write IP addresses. On the next integer second, we write
     the class E IPv4 address (255.255.255.255 = 0xFFFFFFFF) as a terminator.
     This terminator signals that the next word is a timestamp.
     
     For this scheme to work across rotated logfiles, we'll call alpaca_spit()
     with a zero timestamp to signal a reset in the stored integer second.
     
     With ~8000 requests per second, this means:
        8000 * (4 bytes)/(IPv4 address) + (8 byte timestamp and terminator)
        ~ 32 kBytes/second
        ~ 115 MBytes/hour
     
     The format is likely still quite compressable because much of the time
     stamp is repeated, and many IPv4 addresses are likely frequent repeats.
     
     N.B. There is currently no error checking on writes.
     */
    
    static time_t this_ts = 0;
    static long terminator = ALPACA_TERM;
    
    if (this_ts == 0) {
        /* Passed in timestamp, ts, is the first for this file */
        (void)fwrite(&ts,ALPACA_WORD,1,fd);
        this_ts = ts;
    }
    else if(ts == 0){
        /* Signal that this file is ending; prepare for next file */
        this_ts = 0;
        return;  /* Don't write an address */
    }
    else if (this_ts != ts) {
        /* New integer second, so mark it */
        (void)fwrite(&terminator, ALPACA_WORD, 1, fd);
        (void)fwrite(&ts,ALPACA_WORD,1,fd);
        this_ts = ts;
    }
    
    (void)fwrite(&a,ALPACA_WORD,1,fd);
}


void alpaca_dumpfile_rotation(void){
    /* Close current file */
    if (fd != NULL) {
        fclose(fd);
        if (debug) {
            fprintf(stderr,"Closed file %s.\n",current_file_name);
        }
    }
    
    /* Shall we make a new one? */
    if (file_count < limit_log_rotations) {
        compose_dumpfile_name(file_count,2);
        
        fd = fopen(current_file_name,"w+");
        if (fd == NULL) {
            fprintf(stderr,"Error opening file %s for writing: %d. Exiting. \n",
                    current_file_name,errno);
            exit(EXIT_FAILURE);
        }
        file_start_t = time(NULL);
        file_count++;
        if (debug) {
            fprintf(stderr, "File rotation successful, opened %s.\n",current_file_name);
        }
    }
    else{
        /* File limit reached, shut it down! */
        pcap_breakloop(handle);
        fd = NULL;
        if (debug) {
            fprintf(stderr, "File rotation limit reached.\n");
        }
    }
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    static u_int64_t count = 0;                 /* packet counter */
    
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;      /* ethernet header */
    const struct sniff_ip *ip;                  /* ip header */
    const struct sniff_udp *udp;                /* udp header */
    
    /*
    struct dump_info_t *dump_info = (struct dump_info_t *)args;
    */
    
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
    
    /* Is it time to rotate files? */
    if (fd != NULL) {
        if ((ts.tv_sec - file_start_t) > (time_t)limit_time_per_file) {
            if (debug) {
                fprintf(stderr,"File %s time limit reached.\n",current_file_name);
            }
            alpaca_spit(fd, 0, ip->ip_src);     /* Special signal that file is ending */
            alpaca_dumpfile_rotation();
        }
    }
    
    /* Are we still saving to disk? Did any file rotation preserve fd? */
    if (fd != NULL) {
        alpaca_spit(fd, ts.tv_sec, ip->ip_src);
    }
    
    /* Have we captured the maximum number of allowed packets? */
    if (count >= limit_packet_count){
        pcap_breakloop(handle);
        if (debug) {
            fprintf(stderr,"Packet count %llu has reached limit; pcap_breakloop() called.\n",count);
        }
        return;
    }
}




// XCode's default main signature:
// int main(int argc, const char * argv[]) {

int main(int argc, char **argv){
    char *dev;                          /* device */
    char errbuf[PCAP_ERRBUF_SIZE];      /* error string placeholder */
    struct bpf_program fp;              /* compiled filter */
    char filter_exp[] = "udp port 123"; /* filter expression */
    
    /*
    struct dump_info_t *dump_info;
    */
    
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
                limit_snaplen = atoi(optarg);
                if(limit_snaplen > MAX_SNAP_LEN){
                    fprintf(stderr,"Restricting snaplen from %d to defined max %d.\n",limit_snaplen,MAX_SNAP_LEN);
                    limit_snaplen = MAX_SNAP_LEN;
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
        fprintf(stderr, "Couldn't get netmask for device %s: %s. Exiiting. \n", dev, errbuf);
        exit(EXIT_FAILURE);
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
    if (pcap_set_snaplen(handle, limit_snaplen) == -1) {
        fprintf(stderr, "Couldn't set snapshot length to %d", limit_snaplen);
        exit(EXIT_FAILURE);
    }
    
    /* Try dropping root */
    username = "shermanj";
    drop_root(username);
    
    
    if (dumpfile_root != NULL) {
        /* We're going to be saving data to disk */
        /*
         dump_info->current_file_name = malloc(PATH_MAX + 1);
         if (dump_info->current_file_name == NULL) {
         fprintf(stderr,"Error on malloc of current_file_name. Exiting.\n");
         exit(EXIT_FAILURE);
         }
         */
        
        /* Compose filename into first argument, with number index and extension */
        compose_dumpfile_name(file_count,2);
        
        fd = fopen(current_file_name,"w+");
        if (fd == NULL) {
            fprintf(stderr,"Error opening file %s for writing: %d. Exiting. \n",
                    current_file_name,errno);
            exit(EXIT_FAILURE);
        }
        else if (debug){
            fprintf(stderr,"Opened dumpfile: %s\n",current_file_name);
        }
        file_start_t = time(NULL);
        file_count++;
    }
    
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
    
    
    if (debug) {
        fprintf(stderr,"Cleaning up...");
    }
    /* Clean up */
    if (fd != NULL) {
        fclose(fd);
    }
    pcap_freecode(&fp);
    pcap_close(handle);
    
    exit(EXIT_SUCCESS);
}
