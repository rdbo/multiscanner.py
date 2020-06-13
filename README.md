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
