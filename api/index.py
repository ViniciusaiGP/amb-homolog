from flask import Flask, request, jsonify
from flask_jwt_extended import *
from flask_cors import CORS
import json
import os

app = Flask(__name__)

# Configuração do Flask-JWT-Extended
app.config['JWT_SECRET_KEY'] = 'secreto'  # Troque isso por uma chave secreta mais segura em um ambiente de produção
jwt = JWTManager(app)

# Simulação de um banco de dados de usuários
users = {
    'admin': '1234'
}

# Verifica se o arquivo JSON existe e, se não, cria uma lista vazia
if not os.path.exists('agent_data.json'):
    with open('agent_data.json', 'w') as file:
        json.dump([], file)

@app.route('/')
def home():
    return '<h1>Meus EndPoints</h1>'

