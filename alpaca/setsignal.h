//
//  setsignal.h
//  alpaca - "A Lightweight PAcket CApturer"
//
//  Jeff A. Sherman (jeff.sherman@nist.gov)
//  Please see license information in file "alpaca.c
//  This header last modified on: 27 March 2015
//
//  The signal handling portion of this program was adopted from the source
//  of tcpdump. The BSD license under which tcpdump was distributed is
//  reprinted in alpaca.c.

#ifndef __alpaca__setsignal__
#define __alpaca__setsignal__

void (*setsignal(int, void(*)(int)))(int);

#endif /* defined(__alpaca__setsignal__) */

