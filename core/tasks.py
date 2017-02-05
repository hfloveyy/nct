#!/usr/bin/env python
# -*- coding:utf-8 -*-
from web import socketio
import time
from web.main import celery

from nct import nct




#nct = Nct("192.168.0.*")
#nct = Nct("10.2.10.*")

@celery.task
def refresh_list():

    data = []

    host_list = nct.refresh_list()
    for host in host_list:
        data.append({'ip':host.ip,'mac':host.mac,'status':host.cut})
    socketio.emit(
        'list', data, namespace='/refresh'
    )


@celery.task
def new_host_up():
    time.sleep(10)
    nct.start_service()

@celery.task
def cut_it(ip,mac):
    ret = nct.cut_it(ip,mac)
    if ret:
        socketio.emit(
            'status', {'start': 'true'},namespace='/cut'
        )
    else:
        socketio.emit(
            'status', {'start': 'false'},namespace='/cut'
        )

@celery.task
def listening(ip,mac,status):
    ret = nct.listen(ip, mac)
    if ret:
        socketio.emit(
            'status', {'start': 'true'},namespace='/listen'
        )
    else:
        socketio.emit(
            'status', {'start': 'false'},namespace='/listen'
        )

@celery.task
def start_mode(mode):
    ret = nct.mode(mode)



def write_policy(ip,mac):
    return nct.policy(ip,mac)













