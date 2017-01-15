# -*- coding:utf-8 -*-
from web import app,socketio
import json
import time
from web.main import celery
import logging
from nct import Nct
from flask import jsonify

nct = Nct(app.config['IP_SECTION'])

#nct = Nct("192.168.0.*")
#nct = Nct("10.2.10.*")

@celery.task
def refresh_list():
    '''
    socketio.emit(
        'my response',{'data':'刷新列表......','status':'alert alert-warning'},namespace = '/refresh'
    )
    '''
    data = []
    #time.sleep(15)
    #host_list, ip_list, mac_list = nct.refresh_list()
    host_list = nct.refresh_list()
    for host in host_list:
        data.append({'ip':host.ip,'mac':host.mac,'status':host.cut})
    socketio.emit(
        'list', data, namespace='/refresh'
    )
    '''
    socketio.emit(
        'my response', {'data': '刷新列表完成','status':'alert alert-success'}, namespace='/refresh'
    )
    '''

@celery.task
def new_host_up():
    time.sleep(10)
    nct.start_service()

@celery.task
def cut_it(ip,mac):
    nct.cut_it(ip,mac)


@celery.task
def listening(ip,mac,status):
    ret = nct.listen(ip, mac)
    print ret
    if ret:
        socketio.emit(
            'status', {'start': 'true'},namespace='/listen'
        )
    else:
        socketio.emit(
            'status', {'start': 'false'},namespace='/listen'
        )




def write_policy(ip,mac):
    return nct.policy(ip,mac)










