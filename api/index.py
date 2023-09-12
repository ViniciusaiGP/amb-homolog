from flask import Flask, request, jsonify
from flask_jwt_extended import *
from flask_cors import CORS
import json
import os
import firebase_admin
from firebase_admin import credentials, firestore
import datetime

keys_from_firebase = {
  "type": "service_account",
  "project_id": "amb-homolog-jwt",
  "private_key_id": "698873dea58b7029caac678d620298af4aefc0c8",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCqQdIF5mZnSZTT\nCXp1xbNiE1TJVre7iSP9UT3HaWFJWGsFnMWyXPBaslehraOPxX/pBcaqJAVGani9\nSNOlNC17MqjfC0o1PENkd2McyzBrKBb5ddagt7TCxxeTk2o4f9XOjC7TRu2AbyjJ\n8sfyfVt4Noorp4VNHROj6JUELwLuMdB7FlZMFDDYThCY5TFDTaDLVcTN5s0A/TgS\nBH5Uk+8vEE3vuwp0V6RquK/H44Dqpq2xIY+Zx1qoepBZnYh2oXR01vHJZoSY92i4\nLTmfiy2W2gtg70h+LwgubitnCDro1WNRmaKutxzOkjozotIo2esQgpKNGDqjP+pP\ncnkBG3cxAgMBAAECggEABOWhwdOvrFbcdfl20T5fe3ms3aGl5Tn7lASrLzojtzVY\n1q98rDWqICGzDY5t/uuiUzR8U1Z35F+Zm3AlzkGi8UEyxD+R4dga5B/e9OwPN3XO\nu1wdUUAXbebGEdOSoY9jue4kRqVqnWAVH0HhaGMcp2eCL+FAn0gv0W4WIymq/ujZ\nxkiF5+f8QJyMgw7s5K42XtXqrwmV1adihxrhAM4DzuaidqXghcVB7QSQPGA0rYKe\nKOEJ/drVnQT55+zpNr5yskStzHCzM3AwmP829F9N3JXYre/e2QI9FSN9bnCeZPFy\nj4x7QC4qHoYXq3BxLkyXD1PeR0aQAgYClStqBf/DJQKBgQDuBnsw1+akNH9fXpK8\n9H54nZ6nwadiBXsOgIbnKglu52iNd9qJmuMxAWXvO4lBnXRXVshAWJDcRp/OL6O+\nW+LDi6kejIzSmtAsz7JiRpYSAV3UtTp9LGm8pQ6cNOs9S0RfLKGrmruFh5jmfHfH\nE3rgBJT7CvqL/zJQTRjweXjCewKBgQC3HT2MVrjeLhaEvF4j9mIYaw/crjs5prvb\nRprGVbnQsLYZHPl4EdhyjyXD0OBIkzvjht4DN1KK5YJbXrHKsc94uXWF8jk3vvLx\nUtgDRRgdXUzHvoJNcNv2eAw7I7XvJLfKBMaxlvtqGFzZR4SX0Rcmw0evzGzSAeUM\nVgIukXFjQwKBgDLPg2Cr1fpbko0jPSPE9XJ+Ay5AcqDEFr7DxQh3usfH8lOwsCAL\nxk/hwobNKMGvAPTb+6dwwIulL9vt44BxUPj5SULSMgWLMsE+HRBJjSOO0x7jCPdL\nkc7JVVMXINhWxuOiPWjKgRlCFuusykze5a4IjF0CvPVBptXpf1dmNtcdAoGAMlOb\nAuMi1A2eqsSKqx+gPk3Ogjxwkpu8rbtt9mzBMRYgNi68cb+V2YZ2Pqc9vTSaFSKQ\nCho+WWZSuYIBI1BTUT7HihTUnPmiE6lNLTjkM83cuFknvtjx23+K/QYHjr5stN0z\nLsPsPXCMtDrvujoBPuoU3cA1eFKE/Sr2Vo4qt7kCgYEAnJgMaIWqD5/8LDGT9g3m\nNCVOWOFe0sV8lwA0Sj92YwwM3xEKjgONHfo/4OUAuHp3+WKaFWZ7wIf2AF/KUaCC\n3kglVowGoYOawW6bTx5nirD/hJgzxf9E0OS7b01xxsC9T+2foTcUBQqnyrKoWmNu\nf7u7/YtAEXPFVDX0OGBeAS0=\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-ijm5w@amb-homolog-jwt.iam.gserviceaccount.com",
  "client_id": "111992220713519929926",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-ijm5w%40amb-homolog-jwt.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}

pag_doc = """
<!DOCTYPE html>
<html>
<head>
    <title>Documentação dos Endpoints da API</title>
    <style>
        /* Estilos CSS internos */
        body {
            font-family: Arial, sans-serif;
        }

        h1 {
            color: #333;
        }

        h2 {
            color: #555;
        }

        h5 {
            color: #555;
        }

        pre {
            background-color: #f5f5f5;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }

        /* Adicione mais estilos conforme necessário */
    </style>
</head>
<body>
    <h1>Documentação dos Endpoints da API</h1>

    <h2>Autenticação</h2>
    <p>Para autenticar e obter um token JWT:</p>
    <pre>
        <strong>GET</strong> /api/Identity/get-token
        Parâmetros:
        {
            "username": "admin"
            "password": "1234"
        }
        Tempo de vida do Token: 1800 segundos.
    </pre>

    <h2>Recursos Protegidos</h2>
    <p>Esses endpoints requerem autenticação com um token JWT válido.</p>

    <h3>Acessar um Recurso Protegido</h3>
    <h5>Necessário o uso do token do login</h5>
    <pre>
        <strong>GET</strong> /recurso_protegido
        
    </pre>

    <h3>Salvar Dados do Agente</h3>
    <p>Salve os dados do agente no Firestore.</p>
    <h5>Necessário o uso do token do login</h5>
    <pre>
        <strong>POST</strong> /api/Agent
        - data (object): Dados do agente a serem salvos
        Parâmetros (JSON):
        {
            "external_reference": "string",
            "status": 0,
            "name": "string",
            "birth_date": "2023-09-11T19:49:15.868Z",
            "gender": 1,
            "position_external_id": "string",
            "shift_name": "string",
            "sector_external_id": "string",
            "external_id": "string"
        }
    </pre>

    <h3>Obter Todos os Dados do Agente</h3>
    <p>Recupere todos os dados do agente do Firestore.</p>
    <h5>Necessário o uso do token do login</h5>
    <pre>
        <strong>GET</strong> /api/Agent
    </pre>

    <h2>Link para ligar com os EndPoints</h2>
    <pre>
        <strong>https://amb-homolog.vercel.app/</strong>
    </pre>
</body>
</html>
"""

cred = credentials.Certificate(keys_from_firebase)
firebase_admin.initialize_app(cred)
db = firestore.client()  # Inicializa o Firestore

app = Flask(__name__)

# Configuração do Flask-JWT-Extended
app.config['JWT_SECRET_KEY'] = 'secreto'  # Troque isso por uma chave secreta mais segura em um ambiente de produção
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(seconds=1800)  # Define o tempo de expiração para 5 segundos
jwt = JWTManager(app)


# Simulação de um banco de dados de usuários
users = {
    'admin': '1234'
}

@app.route('/')
def home():
    return pag_doc, 200, {'Content-Type': 'text/html; charset=utf-8'}

# Rota para autenticar e obter o token JWT
@app.route('/api/Identity/get-token', methods=['GET'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Verifica se o usuário e senha são válidos
    if username in users and users[username] == password:
        # Define a data de expiração para 5 segundos a partir do momento atual
        expires = datetime.timedelta(seconds=1800)
        # Cria um token de acesso JWT com tempo de expiração
        access_token = create_access_token(identity=username, expires_delta=expires)
        # Retorna o token de acesso com o tempo de expiração em segundos
        return {'access_token': access_token, 'expires_in': 1800}, 200
    else:
        return {'message': 'Credenciais inválidas'}, 401


# Rota protegida que requer autenticação com JWT
@app.route('/recurso_protegido', methods=['GET'])
@jwt_required()
def recurso_protegido():
    current_user = get_jwt_identity()
    return {'message': f'Olá, {current_user}! Este é um recurso protegido.'}

# Função para salvar os dados do agente no Firestore
def save_agent_data(data):
    try:
        agents_ref = db.collection('agents')
        new_agent_ref = agents_ref.add(data)
        return new_agent_ref.id  # Retorne o ID do novo documento
    except Exception as e:
        return str(e)

# Rota para receber os dados e salvá-los no Firestore
@app.route('/api/Agent', methods=['POST'])
@jwt_required()
def post_agent_data():
    try:
        data = request.json  # Obtém os dados do corpo da solicitação em formato JSON
        new_agent_id = save_agent_data(data)  # Chama a função para salvar os dados
        return jsonify({'message': 'Dados do agente foram salvos com sucesso!', 'agent_id': new_agent_id}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Rota para obter todos os dados do Firestore
@app.route('/api/Agent', methods=['GET'])
@jwt_required()
def get_all_agent_data():
    try:
        agents_ref = db.collection('agents')
        all_data = [doc.to_dict() for doc in agents_ref.stream()]
        return jsonify(all_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500