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
import re

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

@app.before_request
def before_request_callback():
    endpoint = limpiarUrl(request.path)
    rutaExcluida = ["/login"]
    if rutaExcluida.__contains__(request.path):
        print("Ruta excluida"+str(request.path))
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        if usuario['rol'] is not None:
            permiso = validarPermiso(endpoint, request.method, usuario['rol']['_id'])
            if not permiso:
                return jsonify({"mensaje":"Permiso denegado"}), 401
        else:
            return jsonify({"mensaje":"Permiso denegado"}), 401

def validarPermiso(endpoint, metodo, id_rol):
    url = data["url-ms-seguridad"]+'/permisos-roles/validar-permiso/rol/'+id_rol
    tienePermiso = False
    headers = {"Content-Type": "application/json; charset = utf-8"}
    body ={
        "url": endpoint,
        "metodo": metodo
    }
    respuesta = requests.get(url, json=body, headers=headers)
    print(respuesta)
    try:
        datos = respuesta.json()
        if "_id" in datos:
            tienePermiso = True
    except:
        pass
    return tienePermiso

def limpiarUrl(url):
    partesUrl = url.split('/')
    for parte in partesUrl:
        if re.search('\\d', parte):
            url = url.replace(parte, '?')
    return url


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

@app.route("/candidatos/<string:id>/partidos/<string:id_partido>", methods=['PUT'])
def asignarPartido(id, id_partido):
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/candidatos/' + id + '/partidos/'+id_partido
    respuesta = requests.put(url, headers=headers)
    return jsonify(respuesta.json())

#MESAS
@app.route("/mesas",methods=['POST'])
def createM():
    datosMesas = request.get_json()
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/mesas'
    respuesta = requests.delete(url, json=datosMesas, headers=headers)
    return jsonify(respuesta.json())

@app.route("/mesas/<string:id>",methods=['GET'])
def getOneM(id):
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/mesas/' + id
    respuesta = requests.get(url, headers=headers)
    return jsonify(respuesta.json())

@app.route("/mesas",methods=['GET'])
def getAllM():
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/mesas'
    respuesta = requests.get(url, headers=headers)
    return jsonify(respuesta.json())

@app.route("/mesas/<string:id>",methods=['PUT'])
def updateM(id):
    datosM = request.get_json()
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/mesas/' + id
    respuesta = requests.put(url, json=datosM, headers=headers)
    return jsonify(respuesta.json())

@app.route("/mesas/<string:id>",methods=['DELETE'])
def deleteM(id):
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/mesas/' + id
    respuesta = requests.delete(url, headers=headers)
    return jsonify(respuesta.json())

#PARTIDOS
@app.route("/partidos",methods=['POST'])
def createP():
    datosMesas = request.get_json()
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/partidos'
    respuesta = requests.delete(url, json=datosMesas, headers=headers)
    return jsonify(respuesta.json())

@app.route("/partidos/<string:id>",methods=['GET'])
def getOneP(id):
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/partidos/' + id
    respuesta = requests.get(url, headers=headers)
    return jsonify(respuesta.json())

@app.route("/partidos",methods=['GET'])
def getAllP():
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/partidos'
    respuesta = requests.get(url, headers=headers)
    return jsonify(respuesta.json())

@app.route("/partidos/<string:id>",methods=['PUT'])
def updateP(id):
    datosP = request.get_json()
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/partidos/' + id
    respuesta = requests.put(url, json=datosP, headers=headers)
    return jsonify(respuesta.json())

@app.route("/partidos/<string:id>",methods=['DELETE'])
def deleteP(id):
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/partidos/' + id
    respuesta = requests.delete(url, headers=headers)
    return jsonify(respuesta.json())

#RESULTADOS
@app.route("/resultados/candidato/<string:id_candidato>/mesa/<string:id_mesa>",methods=['POST'])
def createR(id_candidato, id_mesa):
    datosR = request.get_json()
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/resultados/candidato/'+id_candidato+'/mesa/'+id_mesa
    respuesta = requests.delete(url, json=datosR, headers=headers)
    return jsonify(respuesta.json())

@app.route("/resultados/<string:id>",methods=['GET'])
def getOneR(id):
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/resultados/' + id
    respuesta = requests.get(url, headers=headers)
    return jsonify(respuesta.json())

@app.route("/resultados", methods=['GET'])
def getAllR():
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/resultados'
    respuesta = requests.get(url, headers=headers)
    return jsonify(respuesta.json())

@app.route("/resultados/<string:id>/candidato/<string:id_candidato>/mesa/<string:id_mesa>",methods=['PUT'])
def updateR(id, id_candidato, id_mesa):
    datosR = request.get_json()
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/resultados/' + id+'/candidato/'+id_candidato+'/mesa/'+id_mesa
    respuesta = requests.put(url, json=datosR, headers=headers)
    return jsonify(respuesta.json())

@app.route("/resultados/<string:id>",methods=['DELETE'])
def deleteR(id):
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/resultados/' + id
    respuesta = requests.delete(url, headers=headers)
    return jsonify(respuesta.json())

@app.route("/reportes/candidato/<string:id_candidato>", methods=['GET'])
def resultados(id_candidato):
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/reportes/candidato/' + id_candidato
    respuesta = requests.get(url, headers=headers)
    return jsonify(respuesta.json())

@app.route("/reportes/resultado_mayor", methods=['GET'])
def getResulMayor():
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/reportes/resultado_mayor'
    respuesta = requests.get(url, headers=headers)
    return jsonify(respuesta.json())

@app.route("/reportes/promedio/candidato/<string:id_candidato>", methods=['GET'])
def promedioCandidatos(id_candidato):
    headers = {"Content-Type": "application/json; charset = utf-8"}
    url = data["url-ms-backend"] + '/reportes/promedio/candidato/' + id_candidato
    respuesta = requests.get(url, headers=headers)
    return jsonify(respuesta.json())


def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data

if __name__ =="__main__":
    data = loadFileConfig()
    print("Servidor corriendo en host: "+data["url-api"]+" puerto: "+str(data["port"]))
    serve(app, host=data["url-api"], port=data["port"])