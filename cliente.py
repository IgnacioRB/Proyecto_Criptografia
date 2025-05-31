# cliente.py – simulación del smartwatch que se autentica con el servidor

# importa librerías estándar necesarias
import socket, os, uuid
from getpass import getpass  # para ocultar la contraseña al ingresarla

# importa funciones personalizadas del gestor de autenticación
from auth_manager import cargar_usuario, verificar_password, descifrar_pem

# importa funciones criptográficas necesarias para ECDSA, ECDH y cifrado simétrico
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1) CREDENCIALES

# solicita el nombre del usuario/dispositivo
usuario = input("[Cliente] Nombre de usuario/dispositivo: ")

# solicita la contraseña de forma oculta
password = getpass("[Cliente] Contraseña: ")

# carga los datos del usuario desde el archivo usuarios.json
data_usr = cargar_usuario(usuario)

# si los datos no existen o la contraseña es incorrecta, termina el programa
if not data_usr or not verificar_password(password, data_usr):
    print("Credenciales inválidas."); exit()

# obtiene el ID único del dispositivo (device_id)
device_id = data_usr["device_id"]

# construye la ruta al archivo PEM de la clave privada
ruta_priv = f"keys/{device_id}_private_key.pem"

# intenta descifrar la clave privada
try:
    priv_key = descifrar_pem(usuario, password, data_usr, ruta_pem=ruta_priv)
    print("✓  Clave privada del cliente cargada.")
except Exception as e:
    # si ocurre un error, termina el programa
    print("Error al abrir la clave privada:", e); exit()

# 2) CLAVE PÚBLICA DEL SERVIDOR

# carga los datos del usuario "servidor"
srv_data = cargar_usuario("servidor")

# obtiene el device_id del servidor
srv_dev_id = srv_data["device_id"]

# abre y carga la clave pública del servidor
with open(f"keys/{srv_dev_id}_public_key.pem", "rb") as f:
    srv_pub_key = serialization.load_pem_public_key(f.read())

# 3) CONEXIÓN TCP

# dirección y puerto del servidor
HOST, PORT = "127.0.0.1", 65432

# crea y abre un socket TCP
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # establece conexión con el servidor
    s.connect((HOST, PORT))

    # 3-a) Enviar nuestro device-id al servidor
    s.sendall(device_id.encode())

    # 3-b) Recibir nonce del servidor y firmarlo con la clave privada
    nonce_srv = s.recv(1024)
    firma_cli = priv_key.sign(nonce_srv, ec.ECDSA(hashes.SHA256()))
    s.sendall(firma_cli)

    # 3-c) Enviar nuestro nonce al servidor
    nonce_cli = uuid.uuid4().bytes
    s.sendall(nonce_cli)

    # recibir y verificar la firma del servidor
    firma_srv = s.recv(256)
    srv_pub_key.verify(firma_srv, nonce_cli, ec.ECDSA(hashes.SHA256()))
    print("✓  Autenticación mutua completa")

    # 4) ECDH EFÍMERO / CLAVE AES

    # genera clave privada efímera para ECDH
    cli_tmp_priv = ec.generate_private_key(ec.SECP256R1())

    # convierte su clave pública efímera a formato PEM
    cli_pub_bytes = cli_tmp_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # envía su clave pública efímera al servidor
    s.sendall(cli_pub_bytes)

    # recibe la clave pública efímera del servidor
    srv_pub_bytes = s.recv(1024)
    srv_tmp_pub = serialization.load_pem_public_key(srv_pub_bytes)

    # realiza el intercambio ECDH para obtener el secreto compartido
    shared = cli_tmp_priv.exchange(ec.ECDH(), srv_tmp_pub)

    # deriva la clave AES a partir del secreto compartido usando HKDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b"handshake data"
    ).derive(shared)

    # crea un objeto AES-GCM con la clave derivada
    #print("[DEBUG] AES key cliente:", aes_key.hex())
    aesgcm = AESGCM(aes_key)
    print("✓  Clave compartida derivada, canal seguro listo")

    # 5) MENSAJE CIFRADO

    # construye un mensaje aleatorio concatenado con saludo
    mensaje = uuid.uuid4().bytes + b"||Hola servidor!!"

    # genera un nonce aleatorio de 12 bytes para cifrar
    nonce_msg = os.urandom(12)

    # cifra el mensaje usando AES-GCM
    ciphertext = aesgcm.encrypt(nonce_msg, mensaje, None)

    # muestra longitud del mensaje cifrado
    print("[DEBUG] Longitud ciphertext:", len(ciphertext))

    # -------- DESCOMENTAR LAS 2 LÍNEAS SIGUIENTES PARA PROBAR INTEGRIDAD ----
    #corrupt = bytearray(ciphertext); corrupt[0] ^= 0x01
    #ciphertext = bytes(corrupt)
    # ------------------------------------------------------------------------

    # envía el nonce y el ciphertext al servidor
    s.sendall(nonce_msg + ciphertext)

    # 6) RESPUESTA DEL SERVIDOR

    # espera respuesta del servidor
    data = s.recv(2048)

    # si el mensaje es muy corto, no es válido
    if len(data) < 12:
        print("No se recibió respuesta")
    else:
        # separa el nonce y el mensaje cifrado
        nonce_r, ctxt_r = data[:12], data[12:]
        try:
            # intenta descifrar la respuesta
            texto = aesgcm.decrypt(nonce_r, ctxt_r, None)

            # si contiene "||", imprime solo la parte del mensaje
            if b"||" in texto:
                print("Respuesta del servidor:",
                      texto.split(b"||", 1)[1].decode())
        except Exception as e:
            # si falla la verificación del tag, se muestra mensaje de error
            print("Error de integridad / autenticidad:", e)
