from flask import Flask, request, jsonify
from flask_jwt_extended import *
from flask_cors import CORS
import json
import os
import firebase_admin
from firebase_admin import credentials, firestore

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

cred = credentials.Certificate(keys_from_firebase)
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

