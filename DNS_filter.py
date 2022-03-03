"""
Auther: Yehonatan Thee
description: this script is do "nslookup" action by using scapy
"""
import sys
import socket
from scapy.layers.dns import DNS
i, o, e = sys.stdin, sys.stdout, sys.stderr
from scapy.all import *
sys.stdin, sys.stdout, sys.stderr = i, o, e

MY_DNS = '185.180.100.65'


def print_ip(dns_packet):
    """
    :param dns_packet: the request packet
    """
    dns_packet.show()
    for i in range(dns_packet[DNS].ancount):
        if dns_packet[DNSRR][i].type != 5:
            print(dns_packet[DNSRR][i].rdata)


def create_dns_packet(user_dns_qname):
    """
    :param user_dns_qname:
    :return: new packet that get by send in revrese user_dns_qname
    """
    updated_name = '.'.join(user_dns_qname.split('.')[::-1]) + ".in-addr.arpa"
    try:
        packet = (IP(dst=MY_DNS) / UDP(sport=24601, dport=53) / \
                         DNS(qdcount=1, rd=1) / DNSQR(qname=updated_name, qtype='PTR'))
        dns_packet = sr1(packet, verbose=0)
    except socket.timeout:
         print("Timeout error!")
    #dns_packet.show()
    return dns_packet


def get_all_cname(dns_packet):
    """
    :param dns_packet: request packet
    :return: all the CNAME in this pakcet
    """
    AllCname = []
    for i in range(dns_packet[DNS].ancount):
        if dns_packet[DNSRR][i].type == 5:
            tempCname = dns_packet[DNSRR][i].rrname.decode()
            AllCname.append(tempCname)
    return AllCname


def main():
    # get parameters from user
    try:
        user_dns_type = sys.argv[-2]
        user_dns_qname = sys.argv[-1]

        if user_dns_type == "-type=PTR":
            # crate reverse send and request
            dns_packet = create_dns_packet(user_dns_qname)
        else:
       # send 1 packet to the address that the user input, and search there by google and get the request to dns_packet
            if(user_dns_qname != ""):
                try:
                    print(user_dns_qname)
                    packet = IP(dst=MY_DNS) / UDP(sport=24601, dport=53) / \
                                 DNS(qdcount=1, rd=1) / DNSQR(qname=user_dns_qname)
                    dns_packet = sr1(packet, verbose=0)

                except socket.timeout:
                    print("Timeout error!")
        # print information about how did we get the address information


        print("customer IP:")
        print(dns_packet[IP].dst)
        print("the DNS requests is sended this IP:")
        print(dns_packet[IP].src)
        #dns_packet.show()

        if user_dns_type != "-type=PTR":
            print("\nAll the IP address of this domain:")
            print_ip(dns_packet)
            AllCname = get_all_cname(dns_packet)
            if AllCname:
                print("\nAll CNAME for this domain:")
                for i in AllCname:
                    print("CNAME:" + i)
        else:
            # the packet is PTR type
            print("\nDomain name:")
            for i in range(dns_packet[DNS].ancount):
                if dns_packet[DNSRR][i].type != 5:
                    print(user_dns_qname + "   ---->    " +
                          dns_packet[DNSRR][i].rdata.decode()[:-1])
    except:
        print("the user did'nt give parameters")

if __name__ == '__main__':
    main()
