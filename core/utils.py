from scapy.all import *
import socket
import json
#scan active host
def active_host(ip_section):
    host_list = my_arping(ip_section)
    ip_list = [x[0] for x in host_list]
    mac_list = [x[1] for x in host_list]
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
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=net), verbose=verbose,
                     filter="arp and arp[7] = 2", timeout=timeout, iface_hint=net, **kargs)
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

def tcp_syn_flood(ip):
    pass

def packet(packet):
    print packet.show()
    print packet[ARP].psrc + '  ' + packet[ARP].pdst

def start_sniff(packet_callback,IPSECTION):

    sniff(filter= "arp and net {0}".format(IPSECTION), prn = packet_callback,count=0,store=0)


if __name__ == "__main__":
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
    print 'aa'