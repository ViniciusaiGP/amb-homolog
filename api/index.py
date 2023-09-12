from flask import Flask, request, jsonify
from flask_jwt_extended import *
from flask_cors import CORS

app = Flask(__name__)

@app.route('/')
def home():
    return '<h1>Meus EndPoints</h1>'

