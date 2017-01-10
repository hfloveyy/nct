from flask import render_template
import logging


from web import app
from web import socketio
from celery import Celery



celery = Celery('core',include='core.tasks')


celery.conf.update(app.config)

from core.tasks import refresh_list,new_host_up

from core.nct import Nct

#nct = Nct("192.168.1.*")











@app.route('/')
def index():
    refresh_list.delay()
    new_host_up.delay()
    return render_template('index.html')

    #nct.get_rules()
    #host_list = nct.get_host_list()
    #hostname_list = nct.get_hostname_list()

    #return 'Hello World!'

    #return render_template('celery.html')



@app.route('/refresh')
def refresh():
    refresh_list().delay()
    return  render_template('index.html')

@app.route('/new')
def new():
    new_host_up.delay()
    return  render_template('index.html')






