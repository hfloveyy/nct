from flask import render_template
import logging


from web import app
from celery import Celery



celery = Celery('core',include='core.tasks')


celery.conf.update(app.config)

from core.tasks import refresh_list

from core.nct import Nct

#nct = Nct("192.168.1.*")











@app.route('/')
def index():
    refresh_list.delay()
    #nct.get_rules()
    #host_list = nct.get_host_list()
    #hostname_list = nct.get_hostname_list()
    return render_template('index.html')
    #return 'Hello World!'

    #return render_template('celery.html')



@app.route('/refresh')
def refresh():
    # nct.get_rules()
    #host_list= nct.refresh_list().delay()
    list = refresh_list.delay()
    #hostname_list = nct.get_hostname_list()
    logging.info(list.result)
    return render_template('index.html',list = list.result)
    #return render_template('index.html', list=host_list,name = hostname_list)


'''
@app.route('/async')
def async():
    async_task.delay()
    return 'Task Complete ...'

@app.route('/task')
def start_background_task():
    backgroud_task.delay()
    return 'Started'


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0',port=9000,debug=True)
'''