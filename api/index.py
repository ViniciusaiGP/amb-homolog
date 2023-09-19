from flask import Flask, request, jsonify
from flask_jwt_extended import *
import datetime
from firebase_admin import credentials, initialize_app
from firebase_admin import db as firebase_db 

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

# Configurações do Firebase Realtime Database
cred = credentials.Certificate(keys_from_firebase)
firebase = initialize_app(cred, {
    "databaseURL": "https://amb-homolog-jwt-default-rtdb.firebaseio.com/"
})
db = firebase_db.reference()  # Use 'reference()' para acessar o Realtime Database

app = Flask(__name__)

# Configuração do Flask-JWT-Extended
app.config['JWT_SECRET_KEY'] = 'secreto'  # Troque isso por uma chave secreta mais segura em um ambiente de produção
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(seconds=1800)  # Define o tempo de expiração para 5 segundos
jwt = JWTManager(app)

# Lista de usuários
users = [
    {
        'login': 'gtfoods_mga',
        'senha': 'gtfoodsmga2023',
        'codfil': '1'
    },
    {
        'login': 'gtfoods_prvi',
        'senha': 'gtfoodsprvi2023',
        'codfil': '29'
    },
    {
        'login': 'gtfoods_pnorte',
        'senha': 'gtfoodspnorte2023',
        'codfil': '37'
    }
]

# Rota para obter um token com base nos dados do usuário
@app.route('/api/Identity/get-token', methods=['GET'])
def get_token():
    data = request.json

    login = data.get('login')
    senha = data.get('senha')

    # Verifica se o usuário e senha correspondem a um usuário na lista
    for user in users:
        if user['login'] == login and user['senha'] == senha:
            # Define a data de expiração para 30 minutos (1800 segundos) a partir do momento atual
            expires = datetime.timedelta(seconds=1800)
            # Cria um token de acesso JWT com tempo de expiração
            access_token = create_access_token(identity=login, expires_delta=expires)
            # Retorna o token de acesso com o tempo de expiração em segundos
            return {'access_token': access_token, 'expires_in': 1800}, 200

    # Se as credenciais não corresponderem, retorna uma resposta de erro
    return {'message': 'Credenciais inválidas'}, 401

# Rota protegida por autenticação com token
@app.route('/api/secure', methods=['GET'])
@jwt_required()
def secure_endpoint():
    current_user = get_jwt_identity()
    return {'message': f'Olá, {current_user}! Este é um recurso protegido.'}

@app.route('/api/Agent', methods=['POST'])
@jwt_required()
def post_agent_data():
    try:
        data = request.json  # Obtenha os dados do corpo da solicitação JSON
        current_user_id = get_jwt_identity()  # Obtenha o ID do usuário atualmente autenticado

        # Recupere a lista existente de agentes ou crie uma lista vazia se não existir
        user_ref = db.child('users').child(current_user_id)
        agents_list = user_ref.child('agents').get()

        if agents_list is None:
            agents_list = []  # Inicialize uma lista vazia

        # Crie um dicionário apenas com os dados do agente
        agent_data = {
            'birth_date': data.get('birth_date', ''),
            'external_id': data.get('external_id', ''),
            'external_reference': data.get('external_reference', ''),
            'gender': data.get('gender', ''),
            'name': data.get('name', ''),
            'position_external_id': data.get('position_external_id', ''),
            'sector_external_id': data.get('sector_external_id', ''),
            'shift_name': data.get('shift_name', ''),
            'status': data.get('status', ''),
            'user_id': current_user_id
        }

        # Adicione o novo agente à lista existente
        agents_list.append(agent_data)

        # Atualize a lista de agentes no Firebase
        user_ref.child('agents').set(agents_list)

        return jsonify({'message': 'Os dados do agente foram salvos com sucesso!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Rota para obter todos os dados do Firebase Realtime Database
@app.route('/api/Agent', methods=['GET'])
@jwt_required()
def get_all_agent_data():
    try:
        agents_data = db.child('agents').get()  # Obter todos os dados da coleção 'agents'
        all_data = agents_data.val()
        return jsonify(all_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
