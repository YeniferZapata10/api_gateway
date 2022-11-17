from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import datetime
import requests
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)
cors = CORS(app)
app.config["JWT_SECRET_KEY"]="#3695sT38D2358/."
jwt = JWTManager(app)

@app.route("/",methods=['GET'])
def test():
    json ={}
    json["mensaje"]="Servidor ejecutándose..."
    return jsonify(json)

@app.route("/login",methods=['POST'])
def create_token():
    datosUsuario = request.get_json()
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-seguridad"]+'/usuarios/validate'
    respuesta = requests.post(url, json = datosUsuario, headers=headers)
    if respuesta.status_code == 200:
        user = respuesta.json()
        expires = datetime.timedelta(hours=12)
        access_token = create_access_token(identity=user,expires_delta=expires)
        return jsonify({"token":access_token, "user_id":user["_id"]})
    else:
        return jsonify({"msg":"Correo o contraseña incorrecta"}), 401

@app.route("/candidatos",methods=['POST'])
def createC():
    datosC = request.get_json()
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"]+'/candidatos'
    respuesta = requests.post(url, json=datosC, headers=headers)
    return jsonify(respuesta.json())

@app.route("/candidatos/<string:id>",methods=['GET'])
def getOneC(id):
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/candidatos/'+id
    respuesta = requests.get(url, headers=headers)
    return jsonify(respuesta.json())

@app.route("/candidatos",methods=['GET'])
def getAllC():
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/candidatos'
    respuesta = requests.get(url, headers=headers)
    return jsonify(respuesta.json())

@app.route("/candidatos/<string:id>",methods=['PUT'])
def UpdateC(id):
    datosC = request.get_json()
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/candidatos/'+id
    respuesta = requests.put(url, json=datosC, headers=headers)
    return jsonify(respuesta.json())

@app.route("/candidatos/<string:id>",methods=['DELETE'])
def DeleteC(id):
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/candidatos/'+id
    respuesta = requests.delete(url, headers=headers)
    return jsonify(respuesta.json())

def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data

if __name__ =="__main__":
    data = loadFileConfig()
    print("Servidor corriendo en host: "+data["url-api"]+" puerto: "+str(data["port"]))
    serve(app, host=data["url-api"], port=data["port"])