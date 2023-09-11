from flask import Flask
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import json
from flask_cors import CORS
import os

app = Flask(__name__)

@app.route('/')
def home():
    return '<h1>Meus EndPoints</h1>'

