#!/usr/bin/env python3
# cliente.py – smartwatch / IoT node que se autentica con el servidor

import socket
import os
import uuid
from getpass import getpass

from auth_manager import cargar_usuario, verificar_password, descifrar_pem
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "localhost"
PORT = 8443

usuario = input("Usuario: ").strip()
contrasena = getpass("Contraseña: ")

usuario_data = cargar_usuario(usuario)
if not usuario_data:
    print("Usuario no encontrado.")
    exit()

if not verificar_password(contrasena, usuario_data):
    print("Contraseña incorrecta.")
    exit()

priv_key = descifrar_pem(usuario, contrasena, usuario_data)
pub_key = priv_key.public_key()

with socket.create_connection((HOST, PORT)) as s:
    # se envía el ID de dispositivo
    s.sendall(usuario_data["device_id"].encode())

    # se recibe el nonce del servidor y su firma
    nonce_servidor = s.recv(32)
    firma_servidor = s.recv(64)

    # se firma el nonce del servidor
    firma_cliente = priv_key.sign(nonce_servidor, ec.ECDSA(hashes.SHA256()))

    # se genera ECDH y se envía la clave pública del cliente
    priv_dh = ec.generate_private_key(ec.SECP256R1())
    pub_dh_bytes = priv_dh.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    s.sendall(pub_dh_bytes)
    s.sendall(firma_cliente)

    # se recibe clave pública ECDH del servidor
    pub_dh_servidor = serialization.load_pem_public_key(s.recv(2000))

    # derivar clave compartida
    shared_key = priv_dh.exchange(ec.ECDH(), pub_dh_servidor)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data"
    ).derive(shared_key)

    mensaje = b"Hola servidor, soy el smartwatch"
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    cifrado = aesgcm.encrypt(nonce, mensaje, None)

    s.sendall(nonce + cifrado)

    respuesta = s.recv(1024)
    print("Respuesta segura recibida:", respuesta.decode(errors="ignore"))
