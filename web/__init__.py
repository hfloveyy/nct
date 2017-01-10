# -*- coding:utf-8 -*-

from flask import Flask
from flask_bootstrap3 import Bootstrap

import eventlet
import os

from flask_socketio import SocketIO


import logging

logging.basicConfig(level=logging.DEBUG,
                format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                datefmt='%a, %d %b %Y %H:%M:%S',
                filename='server.log',
                filemode='w')

#################################################################################################
#定义一个StreamHandler，将INFO级别或更高的日志信息打印到标准错误，并将其添加到当前的日志处理对象#
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
console.setFormatter(formatter)
logger = logging.getLogger('nct').addHandler(console)
##################################################################################################
eventlet.monkey_patch()

app = Flask(__name__)

here = os.path.abspath(os.path.dirname(__file__))

app.config.from_pyfile(os.path.join(here,'../config/celeryconfig.py'))
app.config.from_pyfile(os.path.join(here,'../config/config.py'))

SOCKETIO_REDIS_URL = app.config['CELERY_RESULT_BACKEND']



socketio = SocketIO(
    app, async_mode = 'eventlet',
    message_queue = SOCKETIO_REDIS_URL
)

bootstrap = Bootstrap(app)

from web import main

from web import about










