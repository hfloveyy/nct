# -*- coding:utf-8 -*-
from flask import render_template,request,redirect,url_for
import logging


from web import app
from web import socketio
from celery import Celery


celery = Celery('core',include='core.tasks')


celery.conf.update(app.config)

from core.tasks import refresh_list,new_host_up,cut_it,listening,write_policy,test_it












@app.route('/')
def index():
    ret = test_it.delay()
    celery.control.broadcast('pool_restart', {'modules': ['core.tasks']})
    #ret.revoke()
    refresh_list.delay()
    #new_host_up.delay()
    return render_template('index.html')





@app.route('/refresh')
def refresh():
    refresh_list.delay()
    return render_template('index.html')



@app.route('/new')
def new():
    new_host_up.delay()
    return redirect(url_for("index"))

@app.route('/newone')
def newone():
    return 'newone'



@app.route('/cut',methods=['POST'])
def cut():
    if request.method == 'POST':
        ip = request.values.get('ip')
        mac = request.values.get('mac')
        cut_it.delay(ip,mac)
        #cut_it(ip,mac)
        return 'true'



@app.route('/listen',methods=['POST'])

def listen():
    if request.method == 'POST':
        ip = request.values.get('ip')
        mac = request.values.get('mac')
        start = request.values.get('start')
        if start == 'start':
            status = 'true'
        else:
            status = 'false'
        #value = listening.delay(ip,mac)
        listening.delay(ip, mac, status)
    return 'true'

@app.route('/test')
def test():
    test_it.delay()
    return 'true'





@app.route('/policy',methods=['POST'])
def policy():
    if request.method == 'POST':
        ip = request.values.get('ip')
        mac = request.values.get('mac')
        if write_policy(ip,mac):
            return 'true'
        else:
            return 'false'







