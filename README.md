# multiscanner.py
Python3 script to scan IPs, CIDRs, networks, ports
```
Usage: 
sudo python3 multiscanner.py <arguments>
-h (--help)[optional]:         display this message
-c (--cidr)[optional]:         interpret target(s) as CIDR(s)
-pr (--port-range)[optional]:  interpret ports parameter as a range (enter 2 ports only)
-p (--ports)[optional]:        specify the ports to scan
-t (--targets):                specify the target(s)
-T (--time-to-live)[optional]: specify the TTL for the sockets
-w (--wait)[optional]:         specify the wait time before timeout
-o (--output)[optional]:       specify the output file
```

```
Examples:
check if website_test.domain is up:
$ sudo python3 multiscanner.py -t website_test.domain
--------------------
scan the ports 80 and 90 of website_test.domain:
$ sudo python3 multiscanner.py -t website_test.domain -p 80 90
--------------------
scan 192.168.0.1 and 192.168.1.1 and check if the ports 80 and 443 of both are opened:
$ sudo python3 multiscanner.py -t 192.168.0.1 192.168.1.1 -p 80 443
--------------------
scan 192.168.0.1 and 192.168.1.1 and check if all the ports between 80 and 443 of both are opened:
$ sudo python3 multiscanner.py -t 192.168.0.1 192.168.1.1 -pr -p 80 443
--------------------
scan 192.168.0.1 to 192.168.0.255 using CIDR:
$ sudo python3 multiscanner.py -c -t 192.168.0.1/24
--------------------
scan 192.168.0.1 to 192.168.0.255 and 192.168.1.1 to 192.168.1.255 using CIDR and check if all the ports between 100 and 200 are opened, and having a timeout of 5 seconds and a time-to-live (TTL) of 120. Also saving the output to the file logs.txt:
$ sudo python3 multiscanner.py -c -t 192.168.0.1/24 192.168.1.1/24 -pr -p 100 200 -w 5 -T 120 -o logs.txt
```
