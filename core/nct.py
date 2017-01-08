from utils import active_host, get_hostname_by_ip, load_rules
#from web.main import celery,socketio
from web import socketio
import time
from web.main import celery


class Nct():
    def __init__(self,ip_section = "192.168.1.*",mode = 1):
        self.ip_section = ip_section
        self.rulesname = 'config/rules.json'
        self.hostname_list = []
        self.rules_mode = mode
        self.host_list,self.ip_list,self.mac_list = active_host(self.ip_section)

    def get_host_list(self):
        self.get_host_after_rules()
        return self.host_list


    def refresh_list(self):

        self.host_list,self.ip_list,self.mac_list = active_host(self.ip_section)
        self.get_host_after_rules()

        return self.host_list,self.ip_list,self.mac_list

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
        #print rules_dict
        for host in self.host_list:
            if rules_dict.has_key(host[0]):
                #print rules_dict[host[0]]
                #print host[1]
                if rules_dict[host[0]] == host[1]:
                    print "host {0} find right mac:{1}!".format(host[0],host[1])
                else:
                    print "host {0} find wrong mac:{1}!".format(host[0], host[1])
            else:
                print "{0} is not in rules ".format(host[0])


        pass

    def cut_it(self):
        pass

if __name__ == '__main__':
    nct = Nct()
    list = nct.refresh_list()
    print type(list)
    print list[0],list[1]