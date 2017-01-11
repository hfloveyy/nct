from scapy.all import *
from utils import active_host, get_hostname_by_ip, load_rules,start_sniff

from web import socketio
from host import Host
import json
import time
import logging
logger = logging.getLogger('nct')

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



    def get_host_list(self):
        self.get_host_after_rules()
        return self.host_list


    def refresh_list(self):
        self.hosts = []
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
        rules_dict = self.get_rules()
        for host in self.host_list:
            if rules_dict.has_key(host[1]) or host[0] in rules_dict.values():
                if rules_dict[host[1]] == host[0] :
                    logger.info("ip: {0} match right mac:{1}!".format(host[0],host[1]))
                    self.hosts.append(Host(host[0],host[1],1))
                else:
                    self.hosts.append(Host(host[0], host[1], 0))
                    logger.info("ip: {0} match wrong mac:{1}!".format(host[0],host[1]))
            else:
                self.hosts.append(Host(host[0], host[1], -1))
                logger.info("ip {0}: is not in rules ,ip is {1}".format(host[0],host[1]))



    def cut_it(self):
        print "cut it now!"

    def packet_callback(self,packet):
        if self.last_packet is None:
            self.last_packet = packet
        if  self.last_packet[ARP].psrc != packet[ARP].psrc or self.last_packet[ARP].hwsrc != packet[ARP].hwsrc:
            rules_dict = self.get_rules()
            if (packet[ARP].psrc, packet[ARP].hwsrc) in self.host_list or packet[ARP].hwsrc == 'c8:3a:35:c9:5d:dc' \
                or packet[ARP].hwsrc == '00:00:00:00:00:00' or packet[ARP].psrc == '0.0.0.0':
                logger.info('pass the host :' + packet[ARP].psrc + ' mac : ' + packet[ARP].hwsrc)
            else:
                ip = packet[ARP].psrc
                mac = packet[ARP].hwsrc
                self.host_list.append((ip, mac))

                if rules_dict.has_key(packet[ARP].hwsrc):
                    if rules_dict[packet[ARP].hwsrc] == packet[ARP].psrc:
                        self.hosts.append(Host(ip,mac,1))
                        logger.info("2. host {0} in rules. mac:{1}!".format(packet[ARP].psrc, packet[ARP].hwsrc))
                    else:
                        self.hosts.append(Host(ip, mac, 0))
                        logger.info("2. host {0} have a wrong ip:{1}!".format(packet[ARP].hwsrc, packet[ARP].psrc))
                else:
                    self.hosts.append(Host(ip, mac, -1))
                    logger.info("2. host {0} is not in rules ,ip is {1}".format(packet[ARP].hwsrc, packet[ARP].psrc))
                socketio.emit(
                    'new_host_up', {'ip': packet[ARP].psrc, 'mac': packet[ARP].hwsrc,'status':self.hosts[-1].cut}, namespace='/new'
                )
        else:
            pass
            #logger.info("drop the packet mac:{0} ip:{1}".format(packet[ARP].hwsrc, packet[ARP].psrc))
        self.last_packet = packet


    def start_service(self):
        start_sniff(self.packet_callback,self.ip_format)




if __name__ == '__main__':
    nct = Nct("192.168.1.*")
    #list = nct.refresh_list()
    nct.start_service()