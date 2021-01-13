import sys
from scapy.all import *
import argparse

listIP = []
# inPutIP = input("請輸入搜尋IP網段( example: 192.168.0 ) ---> ")
inPutIP = "192.168.1"
def scan(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answerListIP = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    for i in range(0,len(answerListIP)):
        client_dict = {"ip": answerListIP[i][1].psrc, "mac": answerListIP[i][1].hwsrc}
        listIP.append(client_dict)
    return listIP

def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

for i in range(0,255):
    print(inPutIP+"."+str(i))
    scan(inPutIP+"."+str(i))

scan_result = scan("0.0.0.0")
print_result(scan_result)