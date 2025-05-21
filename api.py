# api.py – backend para interacción con frontend smartwatch
from flask import Flask, request, jsonify
from auth_manager import cargar_usuario, verificar_password
from server import autenticar_dispositivo_para_api  # función simulada

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    datos = request.json
    usuario = datos.get("usuario")
    password = datos.get("password")

    data_usr = cargar_usuario(usuario)
    if not data_usr or not verificar_password(password, data_usr):
        return jsonify({"status": "error", "mensaje": "Credenciales inválidas"}), 401

    return jsonify({"status": "ok", "mensaje": "Autenticación exitosa"}), 200

@app.route("/mutua", methods=["POST"])
def mutua():
    datos = request.json
    device_id = datos.get("device_id")

    resultado = autenticar_dispositivo_para_api(device_id)
    return jsonify(resultado)

if __name__ == "__main__":
    app.run(port=5000)
