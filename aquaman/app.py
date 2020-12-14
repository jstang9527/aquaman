# coding=utf-8
from flask import Flask, jsonify, render_template
from random import sample
from string import digits, ascii_lowercase
from aquaman.urls import register_api
from application import settings
from flask_swagger import swagger


def create_app():
    in_app = Flask(__name__)
    return register_api(in_app)


app = create_app()
app.config['SECRET_KEY'] = ''.join(sample(digits + ascii_lowercase, 10))


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/spec')
def spec():
    swag = swagger(app)
    swag['info']['title'] = settings.SWAGGER_TITLE
    swag['info']['version'] = settings.VERSION
    swag['info']['description'] = settings.SWAGGER_DESC
    return jsonify(swag)


@app.route('/swagger')
def swagger_index():
    return render_template("swagger/index.html", **{
        "url": "http://" + settings.SWAGGER_HOST + ":" + str(settings.WEB_PORT) + "/spec"
    })
