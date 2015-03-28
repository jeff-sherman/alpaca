//
//  setsignal.c
//  alpaca - "A Lightweight PAcket CApturer"
//
//  Jeff A. Sherman (jeff.sherman@nist.gov)
//  Please see license information in file "alpaca.c
//  This header last modified on: 27 March 2015
//
//  The signal handling portion of this program was adopted from the source
//  of tcpdump. The BSD license under which tcpdump was distributed is
//  reprinted in alpaca.c.

#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include "setsignal.h"

/* Just assume for now that system has sigaction() */
void (*setsignal (int sig, void (*func)(int)))(int){
    struct sigaction old, new;
    
    /* 
     We potentially spawn child processes with fork() to do automated 
     compression of rotated logfiles. We'll want to modify our chandling of 
     SIGCHLD signals so that we don't have to wait() on finished child processes
     in order to dismiss them. Otherwise, "zombie" processes can pile up.
     
     For all other signals, we just denote a callback function for handling 
     them.
     */
    memset(&new, 0, sizeof(new));
    new.sa_handler = func;
    if (sig == SIGCHLD){
        new.sa_flags = SA_NOCLDWAIT;
    }
    if  (sigaction(sig, &new, &old) < 0)
        return (SIG_ERR);
    
    return (old.sa_handler);
}
