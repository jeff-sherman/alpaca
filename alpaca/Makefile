# Makefile for alpaca - "A Lightweight PAcket CApturer"
# Last edited 11 March 2015, jeff.sherman@nist.gov (x3511)
#
# Typical usage:
#     % make clean
#     % make

all: alpaca

alpaca.o:
	cc -Wall -c alpaca.c

setsignal.o:
	cc -Wall -c setsignal.c

alpaca: setsignal.o alpaca.o
	cc -Wall -lpcap alpaca.o setsignal.o -o alpaca

clean:
	rm -f *.o *.core alpaca

clean_logs:
	rm -f alpaca_out*

