//
//  alpaca.c
//  alpaca - "A Lightweight PAcket CApturer"
//
//  Created by Sherman, Jeffrey A. on 3/4/15.
//  Copyright (c) 2015 Sherman, Jeffrey A. All rights reserved.
//
//  Copying liberally from Tim Carsten's excellent demonstration:
//  http://www.tcpdump.org/sniffex.c
//
//  and the source of tcpdump-4.6.2. I think the latter is pretty spiffy, so
//  where appropriate I will steal some its argument syntax and feature set.

/*
 WHAT:
 Packet capture routine using libpcap, trimmed for a special purpose.
 
 We intend to run it for long periods, hence the name possibilities:
 
 alpaca     - "ALways PAcket CApturing"  or,                ,
            - "A Lightweight PAcket CApturer"              ~)
                                                            (_---;
                                                             /|~|\
USAGE:                                                      / / /|        ejm97
 Compile on FreeBSD with included Makefile:
    % make clean
    % make
 
 Run with:
    #alpaca -h   to print detailed usage information and exit.
    #alpaca -d   to print lots of debugging messages to stderr.
    #alpaca -dd  to print a summary line per packet processed.
    #alpaca -ddd to list several adjustable program parameters.

    #alpaca -C 12 -B 20.5 -W 24 -G 3600 -u jsherman -o -z
    Captures until the first of following limit conditions are met:
        a) 12 billion packets processed (-C option)
        b) 20.5 GB of raw data is written (-B option)
        c) 24 log files are filled, with 1 hour alloted per log file (-W and -G)
    We drop root privs in exchange for user "jsherman" (-u), do automatic
    compression (-z) of old logfiles, overwriting (-o) when necessary.
 
 WHY:
 A tcpdump on a NIST timeserver for port 123 traffic yeilds ~1.6 GB of data
 per hour.
 
 We want... less. Perhaps just a timestamped list of client IP addresses to
 answer pertinent questions like:
 a) How many unique IP client addresses do we see over a month?
 b) What is the distribution of traffic over the work week, around DST
 transitions, leap second months, long weekends, etc. ?
 c) What is the temporal distribution of very frequent/infrequent requesting 
 IPs and abuse traffic?
 
 WHO:
 Useful idiot, Jeff A. Sherman (jeff.sherman@nist.gov, x3511)
 
 HOW:
 The built-in packet filter and libpcap will do the heavy lifting.
 
 We define a filter string for packets we are interested in, like "udp port
 123", which libpcap_compile() turns into packet-filter bytecode. The low-
 level packet filter efficiently tosses us matching packets for processing.
 
 When we get a packet, we'll log what little information we want, how we
 want, and throw away the rest.
 
 Because I envision running this program for long intervals, let's set the
 following aspirational design goals:
 
 1. At the earliest opportunity---right after opening the packet capture
 device (/dev/bpf)---we'll drop root privileges. So I should learn
 how to do that.
 
 2. Even if we only logged 12 bytes per packet, logfiles would still
 grow at a rate ~330 MB/hour (representative of time-a, for example).
 So, we want a mechanism for rotating logfiles and compressing old log
 files automatically.
 
 3. Ideally, we should implement command-line parameters for termination
 upon a certain number of captured packets, total run time, etc. Safe
 default values will be used if command-line arguments are absent.
 
 4. I need to be CAREFUL because crashing a live system is UNACCEPTABLE.
 
 5. This latter goal is especially difficult because I barely know what I
 am doing. So, I will attempt to learn and practice modern C conventions and 
 plan to steal very liberally from clear and successful code such as tcpdump.
 
 For now the output file format is flexible. Suggest file extension: ".spit"
 for Special Packet Information Tally.
 
 WHEN:
 Last significant documentation update: March 10, 2015 -jas.
 
 */

#define APP_NAME                    "alpaca"
#define APP_FILE_EXTENSION          "spit"
#define APP_VERSION_MAJOR           0
#define APP_VERSION_MINOR           1

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/cdefs.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <getopt.h>

/* Some OS-depend #defines, currently only relevant for my Mac */
#include "alpaca-config.h"

/* On FreeBSD v6, need to include for get/set process priority */
#ifndef MAC_OS_X
#include <sys/resource.h>
#endif

/* Signal handling */
#include <signal.h>
#include "setsignal.h"
#include <sys/wait.h>

/* Inlcude pwd.h and uuid.h to support dropping root privileges */
#include <pwd.h>
#ifdef MAC_OS_X
#include <uuid/uuid.h>
#else
#include <uuid.h>
#endif

/* Include pcap and some networking libraries */
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "alpaca-ethernet.h"

#define THOUSAND                    (u_int64_t)1000
#define MILLION                     THOUSAND * THOUSAND
#define BILLION                     THOUSAND * MILLION
#define KB                          (u_int64_t)1024
#define MB                          KB * KB
#define GB                          KB * MB

/* 
   For now, define a low default packet count so accidental launches and
   quick debugging trials don't become epics.
*/
#define DEFAULT_PACKET_COUNT_LIMIT  1 * THOUSAND
#define MAX_PACKET_COUNT_LIMIT      20 * BILLION

#define DEFAULT_BYTES_WRITTEN_LIMIT 10 * GB
#define MAX_BYTES_WRITTEN_LIMIT     40 * GB

#define DEFAULT_SNAP_LEN            68      /* 90 gets a whole NTP packet */
#define MAX_SNAP_LEN                1518

#define DEFAULT_LOG_ROTATE_SECONDS  60
#define MAX_LOG_ROTATE_SECONDS      3600

#define DEFAULT_NUMBER_LOG_FILES    3
#define MAX_NUMBER_LOG_FILES        672     /* 672 hours = 4 weeks */
#define DEFAULT_FILE_INDEX_CHARS    3

#define DEFAULT_STATS_ALARM_SECONDS 900      /* 900 s = 15 minutes */

#define DEFAULT_COMPRESS_MODE       0       /* Default no compression */
#define DEFAULT_OVERWRITE_MODE      0
#define DEFAULT_STATS_MODE          0

#define DEFAULT_SPITFILE_ROOT       "alpaca_out"
#ifndef PATH_MAX
#define PATH_MAX                    1024
#endif
#ifndef USER_MAX
#define USER_MAX                    32      /* Maximum userid length */
#endif

/*
 XCode seems to have some brain damage; it doesn't set the working directory 
 correctly when debugging the process as root. Yes, I adjusted the field in the
 "build scheme" dialog box; it doesn't seem to care.
 */
#ifdef  MAC_OS_X
#define DEFAULT_PATH_FROM_CWD   "/Users/shermanj/"
#else
#define DEFAULT_PATH_FROM_CWD   ""
#endif
#define DEFAULT_USERNAME        "nobody"


/* Shamefully use globals; set safe defaults where appropriate */
u_short   debug_level = 0;
pcap_t    *handle;                          /* libpcap handle */
char      filter_exp[] = "udp port 123";    /* filter expression */

char      username[USER_MAX]    = DEFAULT_USERNAME;

u_short   limit_snaplen         = DEFAULT_SNAP_LEN;
u_int64_t limit_packet_count    = DEFAULT_PACKET_COUNT_LIMIT;
u_int64_t limit_bytes_written   = DEFAULT_BYTES_WRITTEN_LIMIT;
int32_t   limit_time_per_file   = DEFAULT_LOG_ROTATE_SECONDS;
int32_t   limit_log_rotations   = DEFAULT_NUMBER_LOG_FILES;
u_short   limit_fileindex_chars = DEFAULT_FILE_INDEX_CHARS;

u_short   stats_mode            = DEFAULT_STATS_MODE;
u_short   compress_mode         = DEFAULT_COMPRESS_MODE;
u_short   overwrite_mode        = DEFAULT_OVERWRITE_MODE;

time_t    program_start_t;
time_t    file_start_t;
u_int64_t bytes_written         = 0;
u_int64_t packet_count          = 0;
int       file_count = 0;
char      dumpfile_dirpath[PATH_MAX]    = DEFAULT_PATH_FROM_CWD;
char      spitfile_root[PATH_MAX]       = DEFAULT_SPITFILE_ROOT;
char      current_file_name[PATH_MAX];
FILE      *fd;


/* Signal handlers */
#define RETSIGTYPE      void
static RETSIGTYPE cleanup(int signo){
    if (debug_level) {
        fprintf(stderr,"Caught signal to cleanup %d.\n",signo);
    }
    pcap_breakloop(handle);
    fflush(NULL);
}
static RETSIGTYPE child_cleanup(int signo){
    /* It's not like I know what I'm doing, but the signal handler "SA_NOCLDWAIT"
       is set in setsignal() for SIGCHLD, so maybe this function isn't necessary.
       The idea here is to guarantee that fork()'ed children responsible for old
       logfile compression don't stay around as zombie processes.
     
       If this function is called, then the wait() ought to allow the process to
       die.
     */
    if (debug_level) {
        fprintf(stderr,"Caught SIGCHLD.\n");
    }
    wait(NULL);
}

RETSIGTYPE print_stats_on_alarm(int signo){
    struct pcap_stat stats;
    float run_hours = (time(NULL)-program_start_t)/3600.0;
    
    pcap_stats(handle, &stats);
    fprintf(stdout,"%s: %.2f hrs. pcap says %u rec'd, %u dropped. Our callback says %llu tallied, %.3e GB written\n",
            APP_NAME,
            run_hours,
            stats.ps_recv,
            stats.ps_drop,
            packet_count,
            (double)bytes_written/(1.0*GB));
    fflush(stdout);
    
    /* Reset alarm signal */
    if (stats_mode) {
        alarm(DEFAULT_STATS_ALARM_SECONDS);
    }
}

static void print_start_date(){
    size_t max = 100;
    char str[max];
    time_t t;
    struct tm *tp;
    
    /* Get current system time and populate tm time/date fields */
    time(&t);
    tp = gmtime(&t);
    if (strftime(str, max, "%F, %T", tp) > 0){
        fprintf(stdout,"%s started at %s.\n",APP_NAME,str);

    }
}

static void print_usage(){
    /*
    fprintf(stdout, "------------------------80 character terminal template-------------------------\n");
    fprintf(stdout, "0        1         2         3        4         5         6         7         8\n");
    fprintf(stdout, "1234567890123456789012345678901234567801234567890123456789012345678901234567890\n");
    fprintf(stdout, "-------------------------------------------------------------------------------\n");
     */
    fprintf(stdout, "Usage: %s -[Sozdh?] [-C maxnum] [-B maxdata] [-W maxnum] [-G seconds]\n",APP_NAME);
    fprintf(stdout, "                        [-s bytes] [-u userid]\n");
    fprintf(stdout, "     -C maxnum    quit after maxnum packets [billions]  (default %.2g, max %.2g)\n",
            (double)(DEFAULT_PACKET_COUNT_LIMIT)/ (1.0*BILLION),
            (double)(MAX_PACKET_COUNT_LIMIT)/ (1.0*BILLION));
    fprintf(stdout, "     -B maxdata   quit after writing maxdata [GBytes]   (default %.2g, max %.2g)\n",
            (double)(DEFAULT_BYTES_WRITTEN_LIMIT)/ (1.0*GB),
            (double)(MAX_BYTES_WRITTEN_LIMIT)/ (1.0*GB));
    fprintf(stdout, "     -W maxnum    quit after maxnum log file rotations  (default %d, max %d)\n",
            DEFAULT_NUMBER_LOG_FILES,MAX_NUMBER_LOG_FILES);
    fprintf(stdout, "     -G seconds   time limit per output file [seconds]  (default %d, max %d)\n",
            DEFAULT_LOG_ROTATE_SECONDS,MAX_LOG_ROTATE_SECONDS);
    fprintf(stdout, "     -s bytes     set packet snapshot length [bytes]    (default %d, max %d)\n",
            DEFAULT_SNAP_LEN,MAX_SNAP_LEN);
    fprintf(stdout, "     -u userid    drop root privliges to this user      (default 'nobody')\n");
    fprintf(stdout, "     -S           print periodic statistics messages    (default no).\n");
    fprintf(stdout, "     -o           overwrite compressed savefiles        (default no).\n");
    fprintf(stdout, "     -z           compress log files when rotated       (default no).\n");
    fprintf(stdout, "     -d           turn most debug messages on.\n");
    fprintf(stdout, "     -dd          print a summary of each packet received to stdout.\n");
    fprintf(stdout, "     -ddd         print program parameters.\n");
    fprintf(stdout, "     -dddd        print program parameters and immediately exit.\n");
    fprintf(stdout, "     -h or -?     display this help message. \n");
    fprintf(stdout, "Exiting.\n");
}

static void print_parameters(){
    /* Function called when -dd is passed in as an argument. */
    /* Print whatever parameters are set.  main() then exits. */
    
    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));
    /*
    fprintf(stdout, "------------------------80 character terminal template-------------------------\n");
    fprintf(stdout, "0        1         2         3        4         5         6         7         8\n");
    fprintf(stdout, "1234567890123456789012345678901234567801234567890123456789012345678901234567890\n");
    fprintf(stdout, "-------------------------------------------------------------------------------\n");
     */
    fprintf(stdout, "Current %s parameters:\n",APP_NAME);
    fprintf(stdout, "Start time (seconds since epoch):         %ld\n",(long)program_start_t);
    fprintf(stdout, "Spitfile root filename:                   %s\n",spitfile_root);
    fprintf(stdout, "BPF filter string:                        %s\n",filter_exp);
    fprintf(stdout, "Packet snapshot length (snaplen bytes):   %d\n",limit_snaplen);
    fprintf(stdout, "Capture time per log file (seconds):      %d\n",limit_time_per_file);
    fprintf(stdout, "Quit after capturing packets (billion):   %.2g\n",(double)limit_packet_count/(1.0*BILLION));
    fprintf(stdout, "Quit after writing data (GBytes):         %.2g\n",(double)limit_bytes_written/(1.0*GB));
    fprintf(stdout, "Quit after log file rotations:            %d\n",limit_log_rotations);
    fprintf(stdout, "Print some statistics periodically:       %d\n",stats_mode);
    fprintf(stdout, "Compress log files upon rotation:         %d\n",(compress_mode > 0));
    fprintf(stdout, "Overwrite (compressed) files:             %d\n",(overwrite_mode > 0));
    fprintf(stdout, "Drop root and become user:                %s\n",username);
    fprintf(stdout, "Current working directory:                %s\n",cwd);
    fprintf(stdout, "Exiting.\n");
}

static void drop_root(){
    struct passwd *pw = NULL;
    
    if (!username) {
        fprintf(stderr,"Trying to drop root with no (or NULL) defined username. Exiting!\n");
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
    
    /* If we're still here, drop was successful */
    if (debug_level) {
        fprintf(stderr,"Successfully dropped from root to user '%s'.\n", username);
    }
}

static void compose_spitfile_name(int cnt){
    char *buffer = malloc(PATH_MAX+1);
    
    if (cnt == 0 && limit_fileindex_chars == 0) {
        if (sprintf(buffer, "%s%s.%s", dumpfile_dirpath, spitfile_root, APP_FILE_EXTENSION) > PATH_MAX){
            fprintf(stderr, "Error composing a filename with too many characters.  Exiting.\n");
            exit(EXIT_FAILURE);
        }
    }
    else{
        if (sprintf(buffer, "%s%s%0*d.%s", dumpfile_dirpath, spitfile_root, limit_fileindex_chars,cnt,APP_FILE_EXTENSION) > PATH_MAX){
            fprintf(stderr, "Error composing a filename with too many characters.  Exiting.\n");
            exit(EXIT_FAILURE);
        }
    }
    strcpy(current_file_name,buffer);
    free(buffer);
}

#define ALPACA_WORD     4
#define ALPACA_TERM     0xFFFFFFFF

void alpaca_spit(register FILE *fd, const time_t ts, const in_addr_t a){
    /*
     Notes about byte ordering:
     So, timestamps (time_t = type long) are written little-endian, at least
     on my Mac. For example,
     
                                    LSB             MSB
     ts = 1 425 664 608 is saved as 0x60 0xEA 0xF9 0x54
     
     Meanwhile, IPv4 addresses are given to us in network byte order, which
     is big-endian (makes-sensian). That is, we're given:
     
                                          MSB             LSB
     a = 132.163.11.126 is given to us as 0x84 0xA3 0x0B 0x7E
     
     If we wrote it to disk like this on an Intel processor, the byte-ordering 
     will be backwards. So, it is important that we convert it (in the callback
     got_packet() routing) to host-byte ordering with a call to ntohl(x).
     
     Likewise, in the analysis code, we'll need to make sure to interpret this
     word as an unsigned long with little-endian encoding, i.e. just like the
     timestamp. This arbitaray choice was made on March 11, 2015.
     
     Notes about an ad-hoc file format:
     With the aim towards maximum efficiency, here's my clever idea. The first
     word we write in a file is the integer seconds timestamp, followed by an
     packet's IPv4 address. For subsequent packets, if the timestamp is unchanged
     (same integer), we only write IP addresses. On the next integer second, we
     write the invalid address (255.255.255.255 = 0xFFFFFFFF) as a terminator.
     This special terminator marks that the next word is the fresh timestamp.
     
     For this scheme to work across rotated logfiles, we must call alpaca_spit()
     with a zero timestamp to cause a reset in the stored integer second.
     
     This is pretty goofy, and maybe I'll do something... No, who am I kidding?
     
     With ~8000 request packets per second, all this hub-bub means an expected
     data accumulation rate of:
     8000 * (4 bytes)/(IPv4 address) + (8 bytes for timestamp and terminator)
     ~ 32 kBytes/second or 115 MBytes/hour or 2.7 GBytes/day or 18.9 GBytes/week
     
     N.B. There is currently no error checking on writes.
     */
    
    static time_t this_ts = 0;
    static long terminator = ALPACA_TERM;
    
    if (this_ts == 0) {
        /* The passed in timestamp, ts, is the first word for this file */
        (void)fwrite(&ts,ALPACA_WORD,1,fd);
        bytes_written += ALPACA_WORD;
        this_ts = ts;
    }
    else if(ts == 0){
        /* This signal means the file is ending. Prepare for next file by
         restting the state of this_ts. Don't write an IPv4 address,
         just return. */
        this_ts = 0;
        return;
    }
    else if (this_ts != ts) {
        /* Mark the new integer second */
        (void)fwrite(&terminator, ALPACA_WORD, 1, fd);
        (void)fwrite(&ts,ALPACA_WORD,1,fd);
        bytes_written += ALPACA_WORD + ALPACA_WORD;
        this_ts = ts;
    }
    
    /* Unless we returned early, always write an IPv4 address */
    (void)fwrite(&a,ALPACA_WORD,1,fd);
    bytes_written += ALPACA_WORD;
}

void compress_logfile(const char *f){
    char fc[PATH_MAX];
    strcpy(fc, f);
    pid_t child_pid;
    char *compress_cmd = "bzip2";           /* fixed parameter for now */
    int exec_return;
    
    /*
     Some notes on compression performance:
     Test run on time-a had 30 minute logfile rotations.
     Compressed file size:   30,330,854 bytes (28.9 MB)
     Uncompressed file size: 38,708,135 bytes
     Savings:                ~ 21%, so a little marginal.
     
     Still going to accumulate ~ 60 MB per hour (10 GB per week!)
     */
    
    child_pid = fork();
    
    if (child_pid != 0) {
        /* Fork gives parent process the child's PID */
        if (debug_level) {
            fprintf(stderr, "For logfile compression, forked child PID %u.\n",child_pid);
        }
        return;
    }
    else{
        /* 
         Fork returns 0 to the child process.
         
         Try to renice the process to use very low resources (high priority
         value). Execute a compression command on the stored filename fc.
         */
        
        if (setpriority(PRIO_PROCESS, 0, PRIO_MAX) != 0){
            fprintf(stderr, "In compress_logfile, error resetting process priority.\n");
        }
        
        if (overwrite_mode) {
            exec_return = execlp(compress_cmd,compress_cmd,"-f",fc,(char *)NULL);
        }
        else{
            exec_return = execlp(compress_cmd,compress_cmd,fc,(char *)NULL);
        }
        
        if (exec_return == -1) {
            fprintf(stderr, "In compress_logfile, %s %s failed with error %s",
                    compress_cmd,fc,strerror(errno));
        }
        else{
            if (debug_level) {
                fprintf(stderr,"Compression of %s successful.\n",fc);
            }
        }
        exit(1);
    }
}


void alpaca_spitfile_rotation(void){
    if (fd != NULL) {
        fclose(fd);
        if (debug_level) {
            fprintf(stderr,"Closed file %s.\n",current_file_name);
        }
        if (compress_mode) {
            compress_logfile(current_file_name);
        }
    }
    
    /* Shall we make a new file? */
    if (file_count < limit_log_rotations) {
        compose_spitfile_name(file_count);
        
        fd = fopen(current_file_name,"w+");
        if (fd == NULL) {
            fprintf(stderr,"Error opening file %s for writing: %d. Exiting. \n",
                    current_file_name,errno);
            exit(EXIT_FAILURE);
        }
        file_start_t = time(NULL);
        file_count++;
        if (debug_level) {
            fprintf(stderr, "File rotation successful, opened %s.\n",current_file_name);
        }
    }
    else{
        /* File limit reached, shut it down! */
        pcap_breakloop(handle);
        fd = NULL;
        if (debug_level) {
            fprintf(stderr, "File rotation limit reached.\n");
        }
    }
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    /*
     This function is the callback for pcap_loop(). We're called whenever a packet
     matches the filter expression. Some general information could be passed in
     using the first argument, but I am a wuss and have opted to use global
     variables for application state information.
     */
    
    /* Declare pointers for packet headers: we'll map raw packet information
     into the defined structure fields.
     */
    const struct sniff_ethernet *ethernet;      /* ethernet header */
    const struct sniff_ip       *ip;            /* ip header */
    const struct sniff_udp      *udp;           /* udp header */
    
    int size_ip;
    //int size_udp;
    
    struct timeval ts = header->ts;             /* pcap timestamp */
    
    packet_count++;
    ethernet =  (struct sniff_ethernet *)packet;
    ip =        (struct sniff_ip*)(packet + SIZE_ETHERNET);
    
    /* Below we're going to make sure we're processing UDP/IP packets. In the general
     case, this ought to be reworked.
     */
    
    size_ip = IP_HL(ip)*4;
    if ((size_ip < 20) && debug_level) {
        fprintf(stderr,"Packet number %llu: invalid IP header length %u bytes.\n", packet_count, size_ip);
        return;
    }
    
    if ((ip->ip_p != IPPROTO_UDP) && debug_level) {
        fprintf(stderr,"Packet number %llu: not UDP. Protocol number is %u.\n", packet_count, ip->ip_p);
        return;
    }
    
    if(debug_level >= 2){
        udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
        fprintf(stderr,"Packet number %llu at %ld.%ld ", packet_count, ts.tv_sec, (long)ts.tv_usec);
        fprintf(stderr,"from src address %s port %u.\n", inet_ntoa(ip->ip_src), ntohs(udp->udp_sport));
    }
    
    /* Is it time to rotate files? */
    if (fd != NULL) {
        if ((ts.tv_sec - file_start_t) > (time_t)limit_time_per_file) {
            if (debug_level) {
                fprintf(stderr,"File %s time limit reached.\n",current_file_name);
            }
            alpaca_spit(fd, 0, ALPACA_TERM); /* Special signal that file is ending */
            alpaca_spitfile_rotation();
        }
    }
    
    /* 
       Are we still saving to disk?
       Did a file rotation preserve fd? 
       Remember to spit addresses out in host byte ordering?
     */
    if (fd != NULL) {
        alpaca_spit(fd, ts.tv_sec,ntohl(ip->ip_src.s_addr));
    }
    
    /* Have we captured the maximum number of allowed packets?  Shut it down! */
    if (packet_count >= limit_packet_count){
        pcap_breakloop(handle);
        if (debug_level) {
            fprintf(stderr,"Packet count %llu has reached limit; pcap_breakloop() called.\n",packet_count);
        }
        return;
    }
}


/*
 // XCode's default main signature, preserved here for posterity:
 int main(int argc, const char * argv[]) {
 */
int main(int argc, char **argv){
    char *dev;                          /* device */
    char errbuf[PCAP_ERRBUF_SIZE];      /* error string placeholder */
    struct bpf_program fp;              /* compiled filter */
    
    bpf_u_int32 mask;                   /* our netmask */
    bpf_u_int32 net;                    /* out IP */
    
    const int cnt = 10 * (int)MILLION;  /* number to capture per loop-around */
    int loop_status = 0;                /* return of pcap_loop */
    bool finished = false;
    
    int op;                             /* a command line argument */
    int dflag=0;                        /* debug level incrementer */
    
    
    /* Setup signal handlers, blatently ripped off from tcpdump */
    void (*oldhandler)(int);
    (void)setsignal(SIGPIPE, cleanup);
    (void)setsignal(SIGTERM, cleanup);
    (void)setsignal(SIGINT,  cleanup);
    (void)setsignal(SIGCHLD, child_cleanup);
    (void)setsignal(SIGALRM, print_stats_on_alarm);
    
    if ((oldhandler = setsignal(SIGHUP, cleanup)) != SIG_DFL) {
        (void)setsignal(SIGHUP, oldhandler);
    }
    
    strncpy(username, DEFAULT_USERNAME, USER_MAX);
    /* On startup, store system time to seconds precision */
    program_start_t = time(NULL);
    if (program_start_t == (time_t)-1) {
        fprintf(stderr,"Error getting system time. Exiting.\n");
        exit(EXIT_FAILURE);
    }
    
    /* Parse command line arguments */
    while((op = getopt(argc, argv, "doC:B:s:u:G:W:Szh")) != -1){
        switch (op) {
            case 'd':           /* Increase debug level */
                dflag++;
                break;
            case 'o':           /* Compressed file overwrite? */
                overwrite_mode++;
                break;
            case 'C':           /* Adjust limit for number of packets */
                limit_packet_count = (u_int64_t)atof(optarg)*BILLION;
                if (limit_packet_count > MAX_PACKET_COUNT_LIMIT) {
                    fprintf(stderr,"Restricting packet limit from ~%.2g billion to defined max ~%.2g billion\n",
                            (double)limit_packet_count,(double)MAX_PACKET_COUNT_LIMIT);
                    limit_packet_count = MAX_PACKET_COUNT_LIMIT;
                }
                break;
            case 'B':           /* Adjust limit for GBytes written */
                limit_bytes_written = (u_int64_t)(atof(optarg)*GB);
                if (limit_packet_count > MAX_BYTES_WRITTEN_LIMIT){
                    fprintf(stderr,"Restricting data write limit from ~%.2g GB to defined max ~%.2g GB\n",
                            (double)limit_bytes_written/GB,(double)MAX_BYTES_WRITTEN_LIMIT/GB);
                }
                break;
            case 's':           /* Adjust PCAP "snapshot bytes" */
                limit_snaplen = atoi(optarg);
                if(limit_snaplen > MAX_SNAP_LEN){
                    fprintf(stderr,"Restricting snaplen from %d to defined max %d.\n",
                            limit_snaplen,MAX_SNAP_LEN);
                    limit_snaplen = MAX_SNAP_LEN;
                }
                break;
            case 'S':           /* Print periodic statistics messages */
                stats_mode++;
                break;
            case 'u':           /* Adjust userid to which we drop from root */
                strncpy(username,optarg, USER_MAX);
                break;
            case 'G':           /* Adjust the time limit per logfile */
                limit_time_per_file = atoi(optarg);
                if (limit_time_per_file < 0) {
                    fprintf(stderr,"Invalid number of seconds for argument -G: %s. Exiting.\n",
                            optarg);
                    exit(EXIT_FAILURE);
                }
                else if (limit_time_per_file > MAX_LOG_ROTATE_SECONDS){
                    fprintf(stderr,"Specified number of seconds per log file %s exceeds maximum.\n \
                            Truncating value to %d",optarg,MAX_LOG_ROTATE_SECONDS);
                    limit_time_per_file = MAX_LOG_ROTATE_SECONDS;
                }
                break;
            case 'W':           /* Adjust the maximum number of log file rotations */
                limit_log_rotations = atoi(optarg);
                if (limit_log_rotations < 0) {
                    fprintf(stderr,"Invalid number of log file rotations given for argument -W: %s. Exiting.\n",
                            optarg);
                    exit(EXIT_FAILURE);
                }
                else if (limit_log_rotations > MAX_NUMBER_LOG_FILES){
                    fprintf(stderr,"Number of log file rotations %s exceeds maximum.\n \
                            Truncating value to %d",optarg,MAX_NUMBER_LOG_FILES);
                    limit_log_rotations = MAX_NUMBER_LOG_FILES;
                }
                break;
            case 'z':           /* Compress old logfiles? */
                compress_mode++;
                break;
            case 'h':   /* drop through */
            case '?':   /* drop through */
            default:    /* print help message if all else fails */
                print_usage();
                exit(EXIT_SUCCESS);
                break;
        }
    }
    
    /* Set the debugging message level */
    if (dflag >= 1) {
        debug_level = 1;
        fprintf(stderr,"%s version %u.%u.\n",
                APP_NAME,APP_VERSION_MAJOR,APP_VERSION_MINOR);
        fprintf(stderr,"Using libpcap version %u.%u.\n",
                PCAP_VERSION_MAJOR,PCAP_VERSION_MINOR);
        print_start_date();
        fprintf(stderr,"Debug level 1 enabled: most actions generate a message.\n");
    }
    
    if (dflag >= 2){
        debug_level = 2;
        fprintf(stderr,"Debug level 2 enabled: print one line per recieved packet.\n");
    }
    
    if (dflag >= 3) {
        debug_level = 3;
        fprintf(stderr,"Debug level 3 enabled: print current parameters.\n");
        print_parameters();
    }
    
    if (dflag > 3) {
        debug_level = 4;
        fprintf(stderr,"Debug level 4 enabled: immediately exit after printing parameters.\n");
        exit(EXIT_SUCCESS);
    }
    
    /* Define the device (network interface on which to packet-capture) */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s.\n", errbuf);
        fprintf(stderr, "Maybe you're not starting as root? Exiting.\n");
        return(EXIT_FAILURE);
    }
    
    /* Get device properties */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s. Exiting. \n",
                dev, errbuf);
        exit(EXIT_FAILURE);
    }
    
    /* Open session in non-promiscuous mode */
    handle = pcap_open_live(dev, limit_snaplen, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s with snaplen %u: %s. Exiting.\n",
                dev, limit_snaplen, errbuf);
        exit(EXIT_FAILURE);
    }
    
    /* Verify we're capturing on an Ethernet device */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s is not an Ethernet. Exiting.\n", dev);
        exit(EXIT_FAILURE);
    }
    
    /* Set pcap to capture only inbound packets */
    if (pcap_setdirection(handle, PCAP_D_IN) == -1) {
        fprintf(stderr, "Couldn't set pcap direction filter. Exiting.\n");
        exit(EXIT_FAILURE);
    }
    
    /* Compile and apply the packet filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s. Exiting.\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s. Exiting.\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    
    if (debug_level) {
        fprintf(stderr, "PCAP ready on device %s, net %u.%u.%u.%u, mask %u.%u.%u.%u.\n",
                dev,
                (net       )  & 0xFF, (net  >>  8)  & 0xFF,
                (net  >> 16)  & 0xFF, (net  >> 24)  & 0xFF,
                (mask      )  & 0xFF, (mask >>  8)  & 0xFF,
                (mask >> 16)  & 0xFF, (mask >> 24)  & 0xFF);
    }
    
    /* Try dropping root; not optional! */
    drop_root();
    
    /* Prepare first .spit file for output */
    if (limit_log_rotations == 0) {
        limit_fileindex_chars = 0;
    }
    else if (limit_log_rotations < 10) {
        limit_fileindex_chars = 1;
    }
    else if(limit_log_rotations < 100){
        limit_fileindex_chars = 2;
    }
    else if(limit_log_rotations < 1000){
        limit_fileindex_chars = 3;
    }
    else{
        fprintf(stderr,"Looks like you've asked for more than 1000 log files!\n");
        fprintf(stderr,"This might be reasonable, but edit the soruce code if you're so sure. Exiting.\n");
        exit(EXIT_FAILURE);
    }
    
    if (spitfile_root != NULL) {
        /* Compose filename into first argument, with number index and extension */
        compose_spitfile_name(file_count);
        fd = fopen(current_file_name,"w+");
        if (fd == NULL) {
            fprintf(stderr,"Error opening file %s for writing: %d. Exiting.\n",
                    current_file_name,errno);
            exit(EXIT_FAILURE);
        }
        else if (debug_level){
            fprintf(stderr,"Opened spitfile: %s\n",current_file_name);
        }
        file_start_t = time(NULL);
        file_count++;
    }
    
    /* Send outselves a SIGALRM to print stats periodically */
    if (stats_mode) {
        alarm(DEFAULT_STATS_ALARM_SECONDS);
    }
    
    /* Ok, launch the pcap_loop with our callback function "got_packet" defined above */
    do{
        loop_status = pcap_loop(handle, cnt, got_packet, NULL);
        switch (loop_status) {
            case 0:
                /* cnt merely expired, let's go around again */
                ;
                break;
            case -1:
                finished = true;
                if (debug_level) {
                    fprintf(stderr,"pcap_loop exited with error status -1: %s.\n",pcap_geterr(handle));
                }
                break;
            case -2:
                finished = true;
                if (debug_level) {
                    fprintf(stderr,"pcap_loop exited with status -2 because pcap_breakloop() called.\n");
                }
                break;
            default:
                finished = true;
                fprintf(stderr,"pcap_loop exited with unexpected status %d; %s.\n",loop_status,pcap_geterr(handle));
                break;
        }
    } while(!finished);
    
    if (debug_level) {
        fprintf(stderr,"Cleaning up...\n");
    }
    /* Clean up */
    if (fd != NULL) {
        fclose(fd);
        if (compress_mode) {
            compress_logfile(current_file_name);
        }
    }
    pcap_freecode(&fp);
    pcap_close(handle);
    exit(EXIT_SUCCESS);
}
