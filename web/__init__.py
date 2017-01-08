from flask import Flask,render_template
from flask_bootstrap3 import Bootstrap

import eventlet
import os

from flask_socketio import SocketIO



eventlet.monkey_patch()

app = Flask(__name__)

here = os.path.abspath(os.path.dirname(__file__))

app.config.from_pyfile(os.path.join(here,'../config/celeryconfig.py'))

SOCKETIO_REDIS_URL = app.config['CELERY_RESULT_BACKEND']



socketio = SocketIO(
    app, async_mode = 'eventlet',
    message_queue = SOCKETIO_REDIS_URL
)



from web import main




bootstrap = Bootstrap(app)







