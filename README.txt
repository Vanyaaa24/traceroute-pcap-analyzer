Assignment 3 - Analysis of IP Protocol
CSc 361: Computer Communications and Networks
 
Author: Vanya Singla
Student ID: V0107173
 
==================================================
HOW TO RUN
==================================================
 
Requirements:
- Python 3.x
- No external libraries required (uses only built-in modules: sys, struct, math)
 
Usage:
    python3 traceroute.py <pcap_file>
 
Example:
    python3 traceroute.py group1-trace1.pcap
    python3 traceroute.py traceroute-frag.pcap
    python3 traceroute.py win_trace1.pcap
 
==================================================
PROGRAM DESCRIPTION
==================================================
 
The program analyzes a pcap trace file captured during a traceroute run.
It automatically detects whether the trace was captured on Linux (UDP-based)
or Windows (ICMP-based) traceroute.
 
Output includes:
- IP address of the source node
- IP address of the ultimate destination node
- IP addresses of intermediate routers (ordered by hop count)
- Protocol field values found in IP headers
- Fragmentation information (number of fragments and last fragment offset)
- Average RTT and standard deviation between source and each destination
 
==================================================
FILES INCLUDED
==================================================
 
- traceroute.py   : Main Python program
- readme.txt      : This file
- r2.pdf          : Requirement 2 analysis report