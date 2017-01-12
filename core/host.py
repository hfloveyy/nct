# -*- coding:utf-8 -*-
class Host():
    def __init__(self,ip,mac,status = '不在策略中'):
        self.ip = ip
        self.mac = mac
        self.cut = status
