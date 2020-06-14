# multiscanner.py
Python3 script to scan IPs, CIDRs, networks, ports
```
[*] Usage:
sudo python3 multiscanner.py <arguments>
-h (--help)[optional]:         display this message
-c (--cidrs):                  add CIDRs to the scan
-r (--port-ranges)[optional]:  add port ranges to the scan (e. g. 100-200)
-p (--port)[optional]:         add single ports to the scan
-i (--ip):                     add single IP addresses to the scan
-t (--time-to-live)[optional]: specify the TTL for the sockets
-w (--wait)[optional]:         specify the wait time before timeout
-o (--output)[optional]:       specify the output file```
```
Examples:
check if website_test.domain is up:
$ sudo python3 multiscanner.py -i website_test.domain
--------------------
scan the ports 80 and 90 of website_test.domain:
$ sudo python3 multiscanner.py -i website_test.domain -p 80 90
--------------------
scan 192.168.0.1 and 192.168.1.1 and check if the ports 80 and 443 of both are opened:
$ sudo python3 multiscanner.py -i 192.168.0.1 192.168.1.1 -p 80-443
--------------------
scan 192.168.0.1 and 192.168.1.1 and check if all the ports between 80 and 443 of both are opened:
$ sudo python3 multiscanner.py -i 192.168.0.1 192.168.1.1 -r 80-443
--------------------
scan 192.168.0.1 to 192.168.0.255 using CIDR:
$ sudo python3 multiscanner.py -c 192.168.0.1/24
--------------------
scan 192.168.0.1 to 192.168.0.255 and 192.168.1.1 to 192.168.1.255 using CIDR and check if all the ports between 100 and 200 are opened, and having a timeout of 5 seconds and a time-to-live (TTL) of 120. Also saving the output to the file logs.txt:
$ sudo python3 multiscanner.py -c 192.168.0.1/24 192.168.1.1/24 -r 100 200 -w 5 -t 120 -o logs.txt
--------------------
scan the CIDRs '192.168.0.1/24' and '192.168.1.1/24' + the IPs '192.168.14.1' and '192.168.14.2' on the port ranges from '50-100' and '400-500' + the ports '800' and '900' with a wait time of '5' seconds and a TTL of '120'. Save the results on 'logs.txt'
$ sudo python3 multiscanner.py -c 192.168.0.1/24 192.168.1.1/24 -i 192.168.14.1 192.168.14.2 -r 50-100 400-500 -p 800 900 -w 5 -t 120 -o logs.txt
--------------------
```

![alt text](https://github.com/rdbo/multiscanner.py/blob/master/multiscanner_output.png)
