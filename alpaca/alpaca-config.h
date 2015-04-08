//
//  alpaca-config.h
//  alpaca - "A Lightweight PAcket CApturer"
//
//  Jeff A. Sherman (jeff.sherman@nist.gov)
//  Please see license information in file "alpaca.c
//  This header last modified on: 27 March 2015
//
#ifndef alpaca_alpaca_config_h
#define alpaca_alpaca_config_h

/* 
 This file is intended as a replacement for a configure script, which I don't 
 yet really understand. Everything was tested on various FreeBSD distributions,
 and in a few cases, my Mac required some special cases, which we catch with a
 single #define here.
 */

// Comment out when on FreeBSD. Linux may require further configuration.
//
// I'm new to this, but the autoconf-like tools seem like a sick joke.
#define MAC_OS_X

#endif
