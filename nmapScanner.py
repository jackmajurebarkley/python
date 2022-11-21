#!/usr/bin/python3
# make sure to install nmap for python: pip3 install python-nmap

import nmap

scanner = nmap.PortScanner()

print("Welcome! This is a simple nmap automation tool")
print("<--------------------------------------------------->")

ip_addr = input("Please enter the target IP: ")
print("You entered ", ip_addr)
type(ip_addr)

resp = input("""\nPlease enter the type of scan you want to run:
                1) SYN ACK Scan
                2) UDP Scan
                3) Comprehensive Scan \n""")
print("You have selected option: ", resp)

if resp == '1':
    print("Nmap version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())

elif resp == '2':
    print("Nmap version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sU')

elif resp == '3':
    print("Nmap version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-65536')