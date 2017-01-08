# -*- coding:utf-8 -*-
from web import socketio
import time
from web.main import celery
import logging
from nct import Nct

nct = Nct("192.168.1.*")



@celery.task
def refresh_list():
    socketio.emit(
        'my response',{'data':'刷新列表...'},namespace = '/refresh'
    )
    #time.sleep(5)
    host_list, ip_list, mac_list = nct.refresh_list()



    socketio.emit(
        'my response', {'data': '刷新列表完成'}, namespace='/refresh'
    )
    return host_list


