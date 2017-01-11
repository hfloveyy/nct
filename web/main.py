from flask import render_template
import logging


from web import app
from web import socketio
from celery import Celery



celery = Celery('core',include='core.tasks')


celery.conf.update(app.config)

from core.tasks import refresh_list,new_host_up,cut_it












@app.route('/')
def index():
    #refresh_list.delay()
    new_host_up.delay()
    #refresh_list()
    #new_host_up()
    return render_template('index.html')





@app.route('/refresh')
def refresh():
    refresh_list.delay()
    #refresh_list()
    return render_template('index.html')

@app.route('/new')
def new():
    new_host_up.delay()
    #new_host_up()
    return  render_template('index.html')



@app.route('/cut')
def cut():
    cut_it.delay()
    return render_template('index.html')






