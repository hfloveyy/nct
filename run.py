#!/usr/bin/env python
from web import app,socketio


socketio.run(app, host='0.0.0.0',port=9000,debug=True)
#app.run(debug = True)
