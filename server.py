import socket, os, uuid
from getpass import getpass
from auth_manager import cargar_usuario, verificar_password, descifrar_pem
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

if __name__ == "__main__":
    usuario  = input("[Servidor] Nombre del servidor: ")
    password = getpass("[Servidor] Contraseña: ")

    data_usr = cargar_usuario(usuario)
    if not data_usr or not verificar_password(password, data_usr):
        print("Credenciales inválidas."); exit()

    srv_device_id = data_usr["device_id"]
    ruta_priv_srv = f"keys/{srv_device_id}_private_key.pem"

    try:
        priv_srv = descifrar_pem(usuario, password, data_usr, ruta_pem=ruta_priv_srv)
        print("✓  Clave privada del servidor cargada.")
    except Exception as e:
        print("Error al abrir la clave privada:", e); exit()

    HOST, PORT = "127.0.0.1", 65432
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT)); s.listen()
        print(f"[Servidor] Escuchando en {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            with conn:
                print("[Servidor] Conexión de", addr)

                device_id = conn.recv(1024).decode().strip()
                cli_pub_path = f"keys/{device_id}_public_key.pem"
                if not os.path.exists(cli_pub_path):
                    print("  · Device-ID desconocido"); continue

                with open(cli_pub_path, "rb") as f:
                    cli_pub = serialization.load_pem_public_key(f.read())

                nonce_srv = uuid.uuid4().bytes
                conn.sendall(nonce_srv)
                firma_cli = conn.recv(256)
                cli_pub.verify(firma_cli, nonce_srv, ec.ECDSA(hashes.SHA256()))

                nonce_cli  = conn.recv(1024)
                firma_srv  = priv_srv.sign(nonce_cli, ec.ECDSA(hashes.SHA256()))
                conn.sendall(firma_srv)

                srv_tmp_priv  = ec.generate_private_key(ec.SECP256R1())
                srv_pub_bytes = srv_tmp_priv.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
                conn.sendall(srv_pub_bytes)

                cli_pub_bytes = conn.recv(1024)
                cli_tmp_pub   = serialization.load_pem_public_key(cli_pub_bytes)
                shared        = srv_tmp_priv.exchange(ec.ECDH(), cli_tmp_pub)

                aes_key = HKDF(algorithm=hashes.SHA256(), length=32,
                               salt=None, info=b"handshake data").derive(shared)
                print("[DEBUG] AES key servidor:", aes_key.hex())
                aesgcm  = AESGCM(aes_key)
                print("  · Canal seguro establecido.")

                try:
                    conn.settimeout(2.0)
                    data = conn.recv(2048)
                    nonce_m, ctxt = data[:12], data[12:]

                    print("[DEBUG] Longitud ciphertext recibido:", len(ctxt))
                    print("[DEBUG] Corrompiendo ciphertext para simular ataque...")
                    corrupt_ctxt = bytearray(ctxt)
                    corrupt_ctxt[-1] ^= 0x01
                    ctxt = bytes(corrupt_ctxt)

                    msg = aesgcm.decrypt(nonce_m, ctxt, None)
                    print("  · Mensaje:", msg.decode(errors="ignore"))

                    nonce_rsp = os.urandom(12)
                    respuesta = uuid.uuid4().bytes + b"||Hola cliente!!"
                    ctxt_rsp  = aesgcm.encrypt(nonce_rsp, respuesta, None)
                    conn.sendall(nonce_rsp + ctxt_rsp)
                    print("  · Respuesta cifrada enviada.")

                except InvalidTag:
                    print("  · Error: integridad inválida (tag corrompido)")
                    conn.sendall(b"BAD_TAG")
                    continue
