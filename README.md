# alpaca
A Lightweight PAcket CApturer

### It's like tcpdump, but less!
Running tcpdump on port 123 of a NIST timeserver yields in ~1.6GB of data per hour. For certain studies, we might only want to record a timestamp an client IP address. So this tool does that.

### Usage example
`alpaca -C 12 -B 20.5 -W 24 -G 3600 -u jsherman -o -z`
captures in-bound NTP packets until the first of the following limit conditions are met:
  1. 12 billion packets are processed (`-C` option)
  2. 20.5 GB of raw data is written to disk (`-B` option)
  3. 24 log files are filled, with 1 hour (3600 seconds) alloted per file (`-W` and `-G` options)

After opening the packet capture device (`/dev/bpf`), we drop root privs in exchange for user `jsherman` (`-u`), automatically compressing (`-z`) rotated logfiles, overwriting (`-o`) if necessary.

In a live test, it produced 55 GB (and counting) of output data without leaking a byte of memory.
