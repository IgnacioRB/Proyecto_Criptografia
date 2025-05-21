# api.py – backend para interacción con frontend smartwatch
from flask import Flask, request, jsonify
from auth_manager import cargar_usuario, verificar_password
from server import autenticar_dispositivo_para_api

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, uuid

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

@app.route("/pulso", methods=["POST"])
def pulso():
    pulso = str(60 + (uuid.uuid4().int % 40)).encode()
    priv_key = ec.generate_private_key(ec.SECP256R1())
    shared = priv_key.exchange(ec.ECDH(), priv_key.public_key())
    aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"handshake data").derive(shared)
    aesgcm = AESGCM(aes_key)

    nonce = os.urandom(12)
    mensaje = uuid.uuid4().bytes + b"||Pulso:" + pulso
    ciphertext = aesgcm.encrypt(nonce, mensaje, None)

    return jsonify({
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "mensaje": mensaje.decode(errors="ignore")
    })

@app.route("/pasos", methods=["POST"])
def pasos():
    pasos = str(500 + (uuid.uuid4().int % 2000)).encode()
    calorias = str(int(pasos.decode()) // 12).encode()

    priv_key = ec.generate_private_key(ec.SECP256R1())
    shared = priv_key.exchange(ec.ECDH(), priv_key.public_key())
    aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"handshake data").derive(shared)
    aesgcm = AESGCM(aes_key)

    nonce = os.urandom(12)
    mensaje = uuid.uuid4().bytes + b"||Pasos:" + pasos + b",Calorias:" + calorias
    ciphertext = aesgcm.encrypt(nonce, mensaje, None)

    return jsonify({
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "mensaje": mensaje.decode(errors="ignore")
    })

if __name__ == "__main__":
    app.run(port=5000)
