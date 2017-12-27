This program takes input from command line and works similar to tcpdump.
It can capture live and if no device is given, it chooses default device. It can also read offline from a pcap file.
It handles all IP protocols like TCP, UDP etc.

While executing please execute as root user(sudo mode).

Sample Input and Output:

Laxmis-MacBook-Pro:NetSecHW2 lkarnati$ make
gcc -o mydump mydump.c -lpcap -w
Laxmis-MacBook-Pro:NetSecHW2 lkarnati$ ls
example.pcap	makefile	mydump		mydump.c
Laxmis-MacBook-Pro:NetSecHW2 lkarnati$ ./mydump -r example.pcap icmp

2013-01-14 12:42:31.752299 c4:3d:c7:17:6f:9b -> 00:0c:29:e9:94:8e type 0x800 len 90
1.234.31.20 -> 192.168.0.200 ICMP 
45 00 00 30 00 00 40 00 2e 06 6a 5a c0 a8 00 c8    E..0..@...jZ....
01 ea 1f 14 00 50 7b 81 bd cd 09 c6 3a 35 22 b0    .....P{.....:5".
70 12 39 08 11 ab 00 00 02 04 05 b4 01 01 04 02    p.9.............

Capture complete.
Laxmis-MacBook-Pro:NetSecHW2 lkarnati$ ./mydump -r example.pcap -s jZ icmp

2013-01-14 12:42:31.752299 c4:3d:c7:17:6f:9b -> 00:0c:29:e9:94:8e type 0x800 len 90
1.234.31.20 -> 192.168.0.200 ICMP 
45 00 00 30 00 00 40 00 2e 06 6a 5a c0 a8 00 c8    E..0..@...jZ....
01 ea 1f 14 00 50 7b 81 bd cd 09 c6 3a 35 22 b0    .....P{.....:5".
70 12 39 08 11 ab 00 00 02 04 05 b4 01 01 04 02    p.9.............

Capture complete.

Reference:
http://www.tcpdump.org/pcap.html
http://www.tcpdump.org/sniffex.c