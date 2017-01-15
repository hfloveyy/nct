# -*- coding:utf-8 -*-
from scapy.all import *
from utils import active_host, get_hostname_by_ip, load_rules,start_sniff_arp,\
    poison_target,restore_target,cut_target,get_mac,start_sniff

from web import socketio,app
from host import Host
import json
import time
import os
import sys
import threading
import signal
from job import Job

import logging
logger = logging.getLogger('nct')
GATEWAY = app.config['GATEWAY']
GATEWAY_MAC = app.config['GATEWAY_MAC']
#IP = app.config['IP']
COUNT = app.config['PACKET_COUNT']
TIME = app.config['TIME']


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
        #self.host_list,self.ip_list,self.mac_list = active_host(self.ip_section)
        self.host_list= active_host(self.ip_section)
        self.get_host_after_rules()
        #return self.host_list,self.ip_list,self.mac_list
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



    def cut_it(self,target_ip,target_mac):
        #conf.verb = 0
        cut_thread = Job(target=cut_target, args=(GATEWAY, GATEWAY_MAC, target_ip, target_mac))
        cut_thread.setDaemon(True)
        cut_thread.start()
        try:
            print "[*] Starting attack  {} mac:{}".format(target_ip,target_mac)
            time.sleep(TIME)#断网十分钟
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

    def listen(self,target_ip,target_mac):
        #conf.verb = 0
        GATEWAY_MAC = get_mac(GATEWAY)
        packet_count = COUNT
        poison_thread = Job(target=poison_target, args=(GATEWAY, GATEWAY_MAC, target_ip, target_mac))
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
            poison_thread.stop()
            #sniff_thread.stop()
            wrpcap('{}.pcap'.format(target_ip), packets)
            # 还原网络配置
            restore_target(GATEWAY, GATEWAY_MAC, target_ip, target_mac)
            return True
        except Exception,e:
            print e
            # 还原网络配置
            restore_target(GATEWAY, GATEWAY_MAC, target_ip, target_mac)
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



    def test(self):
        t = Job(target=self.mythread,args=(1,2))
        t.setDaemon(True)
        #t.join()
        t.start()
        print 'here'
        time.sleep(5)
        print t
        t.stop()
        #os.kill(os.getpid(), signal.SIGINT)

    def mythread(self,a,b):
        while True:
            print 'mythread'
            #print time.time()
            time.sleep(1)

if __name__ == '__main__':
    nct = Nct()
    #nct.cut_it('192.168.1.101','64:9a:be:8d:d7:24')
    #nct.listen('192.168.1.101','64:9a:be:8d:d7:24')
    #list = nct.refresh_list()
    #nct.start_service()
    nct.test()