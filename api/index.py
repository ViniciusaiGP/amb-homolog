from flask import Flask, request, jsonify
from flask_jwt_extended import *
from flask_cors import CORS
import json
import os
import firebase_admin
from firebase_admin import credentials, firestore

cred = credentials.Certificate("amb-homolog-jwt-firebase-adminsdk-ijm5w-698873dea5.json")
firebase_admin.initialize_app(cred)
db = firestore.client()  # Inicializa o Firestore

app = Flask(__name__)

# Configuração do Flask-JWT-Extended
app.config['JWT_SECRET_KEY'] = 'secreto'  # Troque isso por uma chave secreta mais segura em um ambiente de produção
jwt = JWTManager(app)

# Simulação de um banco de dados de usuários
users = {
    'admin': '1234'
}



@app.route('/')
def home():
    return '<h1>Meus EndPoints</h1>'

