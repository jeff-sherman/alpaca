# Makefile for alpaca - "A Lightweight PAcket CApturer"
# Last edited 11 March 2015, jeff.sherman@nist.gov (x3511)
#
# Typical usage:
#     % make clean
#     % make
#
# 

CC = cc
CFLAGS = -Wall -O2

all: alpaca

alpaca.o:
	$(CC) $(CFLAGS) -c alpaca.c

setsignal.o:
	$(CC) $(CFLAGS) -c setsignal.c

alpaca: setsignal.o alpaca.o
	$(CC) $(CFLAGS) -lpcap alpaca.o setsignal.o -o alpaca

clean:
	rm -f *.o *.core alpaca

clean_logs:
	rm -f alpaca_out*
