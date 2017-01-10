# -*- coding:utf-8 -*-
from web import app
from flask import render_template
import os
import random
import linecache

@app.route('/about')
def about():
    print(os.getcwd())
    basedir = os.path.abspath(os.path.dirname(__file__))
    filename = basedir +'/skill.txt'
    with open(filename) as f:
        lines = f.readlines()
        random_num = random.randint(1,len(lines))
        string = linecache.getline(filename,random_num).decode('utf-8')
    return render_template('about.html',str = string)