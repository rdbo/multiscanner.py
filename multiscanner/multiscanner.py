import socket
import argparse
import datetime
import time
import netaddr
from scapy.all import *

def usage():
    print("[*] Usage: ")
    print(f"sudo python3 multiscanner.py <arguments>")
    print(f"-h (--help)[optional]:         display this message")
    print(f"-c (--cidr)[optional]:         interpret target(s) as CIDR(s)")
    print(f"-pr (--port-range)[optional]:  interpret ports parameter as a range (enter 2 ports only)")
    print(f"-p (--ports)[optional]:        specify the ports to scan")
    print(f"-t (--targets):                specify the target(s)")
    print(f"-T (--time-to-live)[optional]: specify the TTL for the sockets")
    print(f"-w (--wait)[optional]:         specify the wait time before timeout")
    print(f"-o (--output)[optional]:       specify the output file")

def multiscan(targets : list, ports : list, wait : float, timetolive : int, output_file : str, is_cidr : bool, is_port_range : bool):
    target_list = []
    port_list = []
    up_targets = []
    up_ports = {}
    delay = 0.75
    init_str = "<< multiscanner.py by rdbo >>"
    separate_str = "--------------------"

    #CIDR
    if(is_cidr == True):
        for target in targets:
            try:
                temp_target_list = [str(ip) for ip in netaddr.IPNetwork(target)]
                target_list += temp_target_list
            except:
                print(f"[!] Error while resolving {target} as CIDR, exiting...")
                exit(0)
    else:
        target_list = targets

    #Port Range
    if(is_port_range == True and len(ports) > 0):
        port_list = [int(port) for port in range(int(ports[0]), int(ports[-1])+1)]
    elif(len(ports) > 0):
        port_list = [int(port) for port in ports]


    try:
        print(init_str)
        time.sleep(delay)
        print(f"[*] Target(s): {', '.join([target for target in targets])}")
        if(is_port_range == True and len(port_list) > 0):
            print(f"[*] Port(s): {port_list[0]}-{port_list[-1]}")
        elif(len(port_list) > 0):
            print(f"[*] Port(s): {[port for port in port_list]}")
        time.sleep(delay)
        print(f"[*] TTL (time to live): {timetolive}")
        time.sleep(delay)
        print(f"[*] Max timeout: {wait}")
        time.sleep(delay)
        if(len(output_file) > 0):
            print(f"[*] Output file: {output_file}")
        time.sleep(delay)
        print(f"[*] Is CIDR: {is_cidr}")
        time.sleep(delay)
        print(f"[*] Is Port Range: {is_port_range}")
        time.sleep(delay)
        print(separate_str)
    except:
        print()
        exit(0)

    begin_scan = time.perf_counter()
    #Scan
    for target in target_list:
        try:
            print(f"[*] Scanning {target}...")
            up_ports[target] = []
            packet = IP(dst=target, ttl=timetolive)/ICMP()
            reply = sr1(packet, timeout=wait, verbose=False)
            if(reply is not None):
                print(f"[*] {target} is up")
                up_targets.append(target)
                for port in port_list:
                    print(f"[*] Scanning {target}:{port}...")
                    socket.setdefaulttimeout(wait)
                    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    reply = soc.connect_ex((target, port))
                    if(reply == 0):
                        print(f"[*] {target}:{port} is up")
                        up_ports[target].append(port)
            else:
                print(f"[*] {target} is down")
            print(separate_str)
        except KeyboardInterrupt:
            print("[!] Interrupted")
            break
        except:
            print(f"[!] Exception while scanning {target}")

    end_scan = time.perf_counter()
    print("[*] Scan finished")
    scan_time = round(end_scan - begin_scan,2)

    begin_write = time.perf_counter()
    #Write to file
    if(len(output_file) > 0):
        try:
            print(f"[*] Writing to file: {output_file}")
            file = open(output_file, "a")
            file.write("\n")
            file.write(separate_str + "\n")
            file.write(init_str + "\n")
            file.write(f"[ {'{date:%Y/%m/%d - %H:%M:%S}'.format(date=datetime.now())} ]\n")
            file.write("\n")
            file.write(f"[*] Scan info \n")
            file.write(f"Target(s): {', '.join([target for target in targets])} \n")
            if(is_port_range == True and len(port_list) > 0):
                file.write(f"Port(s): {port_list[0]}-{port_list[-1]}\n")
            elif(len(port_list) > 0):
                file.write(f"Port(s): {[port for port in port_list]}\n")
            else:
                file.write(f"Port(s): None\n")
            file.write(f"Max timeout: {wait}\n")
            file.write(f"TTL (time to live): {timetolive}\n")
            file.write(f"CIDR Enabled: {str(is_cidr)}\n")
            file.write(f"Port Range Enabled: {str(is_port_range)}\n")
            file.write("\n")
            file.write("[*] Results\n")

            for target in target_list:
                if(target in up_targets):
                    if(len(ports) == 0 or len(up_ports[target]) == 0):
                        file.write(f"{target} : up\n")
                    else:
                        file.write(f"{target} : [")
                        file.write(', '.join([str(port) for port in up_ports[target]]))
                        file.write(f"]\n")
                else:
                    file.write(f"{target} : down\n")
            print("[*] Writing finished")
        except:
            print(f"[!] Exception while writing to {output_file}")
    end_write = time.perf_counter()
    write_time = round(end_write - begin_write, 2)

    print(separate_str)
    print("[*] Status")
    print(f"[*] Finished scan in {scan_time} second(s)")
    if(len(output_file) > 0):
        print(f"[*] Finished writing in {write_time} second(s)")
        print(f"[*] Saved results to {output_file}")

    print(separate_str)

if (__name__ == "__main__"):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h", "--help", action="store_true", dest="help", default="False")
    parser.add_argument("-c", "--cidr", action="store_true", dest="is_cidr", default="False")
    parser.add_argument("-t", "--targets", type=str, nargs="+", action="store", dest="targets", default="")
    parser.add_argument("-o", "--output", type=str, action="store", dest="output", default="")
    parser.add_argument("-pr", "--port-range", action="store_true", dest="is_port_range", default="False")
    parser.add_argument("-p", "--ports", type=str, nargs="+", action="store", dest="ports", default="")
    parser.add_argument("-T", "--ttl", type=int, action="store", dest="ttl", default="64")
    parser.add_argument("-w", "--wait", type=float, action="store", dest="wait", default="1")
    args = parser.parse_args()
    try:
        help_param = args.help
        target_list = args.targets
        port_list = args.ports
        wait = args.wait
        output = args.output
        ttl = args.ttl
        is_cidr = args.is_cidr
        is_port_range = args.is_port_range
    except:
        usage()
        exit(0)

    if(help_param == True or len(target_list) == 0 or wait < 0 or ttl < 0 or (is_port_range == True and len(port_list) != 2)):
        usage()
        exit(0)
    multiscan(target_list, port_list, wait, ttl, output, is_cidr, is_port_range)