# -*- coding:utf-8 -*-
from web import app,socketio
import json
import time
from web.main import celery
import logging
from nct import Nct

nct = Nct(app.config['IP_SECTION'])
#nct = Nct("192.168.0.*")
#nct = Nct("10.2.10.*")

@celery.task
def refresh_list():
    socketio.emit(
        'my response',{'data':'刷新列表......','status':'alert alert-warning'},namespace = '/refresh'
    )
    #time.sleep(15)
    #host_list, ip_list, mac_list = nct.refresh_list()
    host_list = nct.refresh_list()
    socketio.emit(
        'empty', {'data': '清空table'}, namespace='/refresh'
    )
    for host in host_list:
        socketio.emit(
        'list', {'ip':host.ip,'mac': host.mac,'status':host.cut}, namespace='/refresh'
    )


    socketio.emit(
        'my response', {'data': '刷新列表完成','status':'alert alert-success'}, namespace='/refresh'
    )

@celery.task
def new_host_up():
    time.sleep(15)
    nct.start_service()










