#!/usr/bin/env python3
import socket, os, uuid
from getpass import getpass
from auth_manager import cargar_usuario, verificar_password, descifrar_pem
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

usuario   = input("[Cliente] Nombre de usuario/dispositivo: ")
password  = getpass("[Cliente] Contraseña: ")

data_usr  = cargar_usuario(usuario)
if not data_usr or not verificar_password(password, data_usr):
    print("Credenciales inválidas."); exit()

device_id = data_usr["device_id"]
ruta_priv = f"keys/{device_id}_private_key.pem"

try:
    priv_key = descifrar_pem(usuario, password, data_usr, ruta_pem=ruta_priv)
    print("✓  Clave privada del cliente cargada.")
except Exception as e:
    print("Error al abrir la clave privada:", e); exit()

srv_data   = cargar_usuario("servidor")
srv_dev_id = srv_data["device_id"]
with open(f"keys/{srv_dev_id}_public_key.pem", "rb") as f:
    srv_pub_key = serialization.load_pem_public_key(f.read())

HOST, PORT = "127.0.0.1", 65432
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(device_id.encode())

    nonce_srv  = s.recv(1024)
    firma_cli  = priv_key.sign(nonce_srv, ec.ECDSA(hashes.SHA256()))
    s.sendall(firma_cli)

    nonce_cli  = uuid.uuid4().bytes
    s.sendall(nonce_cli)
    firma_srv  = s.recv(256)
    srv_pub_key.verify(firma_srv, nonce_cli, ec.ECDSA(hashes.SHA256()))
    print("✓  Autenticación mutua completa")

    cli_tmp_priv  = ec.generate_private_key(ec.SECP256R1())
    cli_pub_bytes = cli_tmp_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    s.sendall(cli_pub_bytes)

    srv_pub_bytes = s.recv(1024)
    srv_tmp_pub   = serialization.load_pem_public_key(srv_pub_bytes)
    shared        = cli_tmp_priv.exchange(ec.ECDH(), srv_tmp_pub)

    aes_key = HKDF(algorithm=hashes.SHA256(), length=32,
                   salt=None, info=b"handshake data").derive(shared)
    
    aesgcm  = AESGCM(aes_key)
    print("✓  Clave compartida derivada, canal seguro listo")

    # Enviar datos reales del smartwatch: pasos + calorías
    pasos = 13
    calorias = 1
    mensaje = f"Pasos: {pasos}, Calorías: {calorias}".encode()
    nonce_msg  = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce_msg, mensaje, None)

    s.sendall(nonce_msg + ciphertext)

    data = s.recv(2048)
    if len(data) < 12:
        print("No se recibió respuesta")
    else:
        nonce_r, ctxt_r = data[:12], data[12:]
        try:
            texto = aesgcm.decrypt(nonce_r, ctxt_r, None)
            if b"||" in texto:
                print("Respuesta del servidor:",
                      texto.split(b"||", 1)[1].decode())
            else:
                print("Respuesta:", texto.decode())
        except Exception as e:
            print("Error de integridad / autenticidad:", e)
