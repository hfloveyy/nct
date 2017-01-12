# -*- coding:utf-8 -*-
from flask import render_template,request,redirect,url_for
import logging


from web import app
from web import socketio
from celery import Celery



celery = Celery('core',include='core.tasks')


celery.conf.update(app.config)

from core.tasks import refresh_list,new_host_up,cut_it,listening,write_policy












@app.route('/')
def index():
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
    return render_template('index.html')



@app.route('/cut')
def cut():
    cut_it.delay()
    return render_template('index.html')

@app.route('/listen',methods=['POST'])
def listen():
    if request.method == 'POST':
        ip = request.values.get('ip')
        value = listening.delay(ip)
        if value.get():
            return 'true'
        else:
            return 'false'




@app.route('/policy',methods=['POST'])
def policy():
    if request.method == 'POST':
        ip = request.values.get('ip')
        mac = request.values.get('mac')
        if write_policy(ip,mac):
            return 'true'
        else:
            return 'false'







