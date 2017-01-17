# -*- coding:utf-8 -*-
from flask import render_template,request,redirect,url_for
import logging


from web import app
from web import socketio
from celery import Celery,platforms


celery = Celery('core',include='core.tasks')


celery.conf.update(app.config)
platforms.C_FORCE_ROOT = True
from core.tasks import refresh_list,new_host_up,cut_it,listening,write_policy












@app.route('/')
def index():
    refresh_list.delay()
    return render_template('index.html')





@app.route('/refresh')
def refresh():
    refresh_list.delay()
    return 'true'



@app.route('/new')
def new():
    new_host_up.delay()
    return 'true'

@app.route('/newone')
def newone():
    return 'newone'



@app.route('/cut',methods=['POST'])
def cut():
    if request.method == 'POST':
        ip = request.values.get('ip')
        mac = request.values.get('mac')
        start = request.values.get('start')
        if start == 'OUT':
            status = 'true'
        else:
            status = 'false'
        cut_it.delay(ip,mac)
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
        listening.delay(ip, mac, status)
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







