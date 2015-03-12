//
//  setsignal.c
//  alpaca
//
//  Created by Sherman, Jeffrey A. on 3/11/15.
//  Copyright (c) 2015 Sherman, Jeffrey A. All rights reserved.
//

#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include "setsignal.h"

void (*setsignal (int sig, void (*func)(int)))(int){
    /* Assume system has sigaction() */
    struct sigaction old, new;
    
    memset(&new, 0, sizeof(new));
    new.sa_handler = func;
    if (sig == SIGCHLD)
        new.sa_flags = SA_NOCLDWAIT;
    if  (sigaction(sig, &new, &old) < 0)
        return (SIG_ERR);
    
    return (old.sa_handler);
}
