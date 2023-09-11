from flask import Flask
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import json
from flask_cors import CORS
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

# Rota para autenticar e obter o token JWT
@app.route('/api/Identity/get-token', methods=['GET'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Verifica se o usuário e senha são válidos
    if username in users and users[username] == password:
        # Cria um token de acesso JWT
        access_token = create_access_token(identity=username)
        return {'access_token': access_token}, 200
    else:
        return {'message': 'Credenciais inválidas'}, 401

# Rota protegida que requer autenticação com JWT
@app.route('/recurso_protegido', methods=['GET'])
@jwt_required()
def recurso_protegido():
    current_user = get_jwt_identity()
    return {'message': f'Olá, {current_user}! Este é um recurso protegido.'}

# Função para obter todos os dados existentes no arquivo JSON
def get_agent_data():
    with open('agent_data.json', 'r') as file:
        return json.load(file)

# Função para salvar os dados do agente no arquivo JSON com um ID único
def save_agent_data(data):
    all_data = get_agent_data()
    new_id = len(all_data) + 1  # Gere um novo ID único
    data['id'] = new_id
    all_data.append(data)
    with open('agent_data.json', 'w') as file:
        json.dump(all_data, file, indent=4)

# Rota para receber os dados e salvá-los em um arquivo JSON
@app.route('/api/Agent', methods=['POST'])
@jwt_required()
def post_agent_data():
    try:
        data = request.json  # Obtém os dados do corpo da solicitação em formato JSON
        save_agent_data(data)  # Chama a função para salvar os dados
        return jsonify({'message': 'Dados do agente foram salvos com sucesso!', 'data': data}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Rota para obter todos os dados do arquivo JSON
@app.route('/api/Agent', methods=['GET'])
@jwt_required()
def get_all_agent_data():
    try:
        all_data = get_agent_data()
        return jsonify(all_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500