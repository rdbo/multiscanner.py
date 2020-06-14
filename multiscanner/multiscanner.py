import socket
import argparse
import datetime
import time
import netaddr
import sys
from scapy.all import *

def usage():
    print("[*] Usage: ")
    print(f"sudo python3 multiscanner.py <arguments>")
    print(f"-h (--help)[optional]:         display this message")
    print(f"-c (--cidrs):                  add CIDRs to the scan")
    print(f"-r (--port-ranges)[optional]:  add port ranges to the scan (e. g. 100-200)")
    print(f"-p (--port)[optional]:         add single ports to the scan")
    print(f"-i (--ip):                     add single IP addresses to the scan")
    print(f"-t (--time-to-live)[optional]: specify the TTL for the sockets")
    print(f"-w (--wait)[optional]:         specify the wait time before timeout")
    print(f"-o (--output)[optional]:       specify the output file")

def multiscan(cidrs : list, ip_addrs : list, port_ranges : list, ports : list, timetolive : int, wait : int, output_file : str):

    #Info

    init_str = "<< multiscanner.py by rdbo >>"
    separate_str = "--------------------"
    delay = 0.5

    print(init_str)
    time.sleep(delay)
    if(len(cidrs) > 0):
        print(f"[i] CIDRs: {[cidr for cidr in cidrs]}")
        time.sleep(delay)
    if(len(ip_addrs) > 0):
        print(f"[i] IP addresses: {[ip for ip in ip_addrs]}")
        time.sleep(delay)
    if(len(port_ranges) > 0):
        print(f"[i] Port ranges: {[pr for pr in port_ranges]}")
        time.sleep(delay)
    if(len(ports) > 0):
        print(f"[i] Ports: {[port for port in ports]}")
        time.sleep(delay)
    print(f"[i] TTL (time to live): {timetolive}")
    time.sleep(delay)
    print(f"[i] Timeout (wait): {wait}")
    time.sleep(delay)
    if(len(output_file) > 0):
        print(f"[i] Output file: {output_file}")
        time.sleep(delay)

    print(separate_str)

    #Variables

    ip_list = []
    up_ip_list = []
    port_list = []
    up_port_list = {}
    proceed_check = False

    #Parse IP addresses
    print("[*] Parsing IP addresses...")
    ip_list += ip_addrs

    for cidr in cidrs:
        try:
            temp_ip_list = [str(ip) for ip in netaddr.IPNetwork(cidr)]
            ip_list += temp_ip_list
        except KeyboardInterrupt:
            print()
            print("[!] Interrupted")
            return 0
        except:
            print(f"[!] Error while parsing \"{cidr}\" as CIDR")
            proceed_check = True

    print("[+] IP addresses parsed")

    #Parse ports
    print("[*] Parsing ports...")
    port_list += [int(port) for port in ports]
    for port in port_ranges:
        try:
            port_arr = str(port).split('-')
            if(len(port_arr) >= 2):
                for p in range(int(port_arr[0]), int(port_arr[-1]) + 1):
                    if(p >= 0):
                        if(p not in port_list):
                            port_list.append(p)
                    else:
                        print(f"[!] Invalid port: \"{p}\"")
            else:
                print(f"[!] Invalid port range string \"{port}\". Try: port1-port2.")
                proceed_check = True
        except KeyboardInterrupt:
            print()
            print("[!] Interrupted")
            return 0
        except:
            print(f"[!] Error while parsing \"{port}\" as a port range")
            proceed_check = True

    print("[+] Ports parsed")

    #Proceed check
    if(proceed_check == True):
        check = input("[#] Errors were found before the start of the scan. Proceed? (y/n): ")
        if(check == 'n' or check == 'N'):
            return 0

    #Scan
    print("[*] Scanning...")
    begin_scan = time.perf_counter()

    for ip in ip_list:
        try:
            print(f"[*] Scanning {ip}...")
            up_port_list[ip] = []
            packet = IP(dst=ip, ttl=timetolive)/ICMP()
            reply = sr1(packet, timeout=wait, verbose=False)
            if(reply is not None):
                print(f"[i] {ip} is up")
                up_ip_list.append(ip)
                for port in port_list:
                    print(f"[*] Scanning {ip}:{port}...")
                    socket.setdefaulttimeout(wait)
                    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    reply = soc.connect_ex((ip, port))
                    if(reply == 0):
                        print(f"[i] {ip}:{port} is up")
                        up_port_list[ip].append(port)
            else:
                print(f"[i] {ip} is down")
        except KeyboardInterrupt:
            print()
            print("[!] Interrupted")
            break
        except:
            print(f"[!] Exception raised while scanning {ip}")
            print(f"[!] {sys.exc_info()[0]}")
        print(separate_str)

    end_scan = time.perf_counter()
    print("[+] Scan finished")
    scan_time = round(end_scan - begin_scan, 2)

    #Write to output file
    begin_write = time.perf_counter()
    if(len(output_file) > 0):
        try:
            print(f"[*] Writing output to: {output_file}")
            file = open(output_file, "a")
            file.write("\n")
            file.write(separate_str + "\n")
            file.write(init_str + "\n")
            file.write(f"[ {'{date:%Y/%m/%d - %H:%M:%S}'.format(date=datetime.now())} ]\n")
            file.write("\n")
            file.write(f"[*] Scan info \n")
            file.write(f"[i] Target(s): [{', '.join([ip for ip in ip_addrs] + [cidr for cidr in cidrs])}]\n")
            if(len(ports) + len(port_ranges) > 0):
                file.write(f"[i] Port(s): [{', '.join([port for port in ports] + [pr for pr in port_ranges])}]\n")
            file.write(f"[i] TTL (time to live): {timetolive}\n")
            file.write(f"[i] Timeout (wait): {wait}\n")
            file.write("\n")
            file.write("[*] Results\n")

            for ip in ip_list:
                if(ip in up_ip_list):
                    if(len(up_port_list) == 0 or len(up_port_list[ip]) == 0):
                        file.write(f"{ip}: up\n")
                    else:
                        file.write(f"{ip} : [")
                        file.write(", ".join([str(port) for port in up_port_list[ip]]))
                        file.write(f"]\n")
                else:
                    file.write(f"{ip} : down")
            
            print("[+] Finished writing")
        except KeyboardInterrupt:
            print("[!] Interrupted")
        except:
            print(f"[!] Exception while writing to file")
    
    end_write = time.perf_counter()
    write_time = round(end_write - begin_write, 2)

    print(separate_str)
    print("[*] Status")
    print(f"[i] Finished scan in {scan_time} second(s)")
    if(len(output_file) > 0):
        print(f"[i] Finished writing in {write_time} second(s)")
        print(f"[i] Saved results to {output_file}")

    print(separate_str)

if (__name__ == "__main__"):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h", "--help", action="store_true", dest="help", default="False")
    parser.add_argument("-c", "--cidrs", type=str, nargs="+", action="store", dest="cidrs", default="")
    parser.add_argument("-i", "--ip", type=str, nargs="+", action="store", dest="ips", default="")
    parser.add_argument("-r", "--port-ranges", type=str, nargs="+", action="store", dest="port_ranges", default="")
    parser.add_argument("-p", "--port", type=str, nargs="+", action="store", dest="ports", default="")
    parser.add_argument("-t", "--time-to-live", type=int, action="store", dest="ttl", default="64")
    parser.add_argument("-w", "--wait", type=float, action="store", dest="wait", default="1")
    parser.add_argument("-o", "--output", type=str, action="store", dest="output", default="")
    args = parser.parse_args()

    try:
        var_help = args.help
        var_cidrs = args.cidrs
        var_ip_addrs = args.ips
        var_output = args.output
        var_port_ranges = args.port_ranges
        var_ports = args.ports
        var_ttl = args.ttl
        var_wait = args.wait
    except:
        print("[!] Unable to parse arguments")
        usage()
        exit(0)

    if(var_help == True or len(var_cidrs) + len(var_ip_addrs) < 1 or var_ttl < 1 or var_wait < 0):
        usage()
        exit(0)
    
    try:
        multiscan(var_cidrs, var_ip_addrs, var_port_ranges, var_ports, var_ttl, var_wait, var_output)
    except KeyboardInterrupt:
        print()
        print("[!] Interrupted")
        exit(0)
    except SystemExit:
        exit(0)
    except:
        print("[!] Exception raised, exiting...")
        exit(0)
