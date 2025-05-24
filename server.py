# server.py  – autenticación mutua + ECDH + AES-GCM

# importa librerías estándar necesarias
import socket, os, uuid
from getpass import getpass

# importa funciones propias para autenticación y manejo de claves
from auth_manager import cargar_usuario, verificar_password, descifrar_pem

# importa módulos de criptografía necesarios para firma, ECDH y cifrado
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag  # excepción para errores de integridad

# ────────────────────────────────────────────────
def autenticar_dispositivo_para_api(device_id: str):
    """Versión reducida para la demo REST: solo comprueba que exista la clave pública."""
    try:
        print(f"[DEBUG] autenticando {device_id}")  # muestra el device_id recibido

        srv_data = cargar_usuario("servidor")  # carga datos del servidor desde JSON
        clave_srv = descifrar_pem("servidor", "servidor123", srv_data)  # descifra clave privada del servidor

        cli_pub_path = f"keys/{device_id}_public_key.pem"  # construye ruta a clave pública del cliente
        if not os.path.exists(cli_pub_path):  # si no existe, se devuelve error
            return {"error": f"No existe {cli_pub_path}"}

        with open(cli_pub_path, "rb") as f:  # abre archivo de clave pública
            cli_pub = serialization.load_pem_public_key(f.read())  # carga la clave pública

        # autenticación simulada para REST (sin firma real)
        nonce_srv = uuid.uuid4().bytes  # genera nonce del servidor
        firma_cli = cli_pub.public_bytes(  # simula una "firma" extrayendo los primeros 8 bytes
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)[:8]

        tmp_priv = ec.generate_private_key(ec.SECP256R1())  # clave privada efímera
        shared = tmp_priv.exchange(ec.ECDH(), tmp_priv.public_key())  # hace ECDH consigo mismo (simulado)
        clave_aes = HKDF(  # deriva clave AES
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data"
        ).derive(shared)

        return {  # devuelve datos simulados al cliente web
            "nonce_servidor": nonce_srv.hex()[:16],
            "firma_cliente": firma_cli.hex(),
            "nonce_cliente": uuid.uuid4().hex[:16],
            "clave_aes": clave_aes.hex()[:16],
        }

    except Exception as e:
        return {"error": str(e)}  # si ocurre error, se devuelve en JSON
# ────────────────────────────────────────────────

# ── ejecuta solo si se corre directamente (no si se importa) ──
if __name__ == "__main__":
    # ── credenciales del operador ─────────────────────────
    usuario = input("[Servidor] Nombre del servidor: ")  # solicita nombre
    password = getpass("[Servidor] Contraseña: ")  # solicita contraseña oculta

    data_usr = cargar_usuario(usuario)  # carga datos del usuario
    if not data_usr or not verificar_password(password, data_usr):  # si no valida, termina
        print("Credenciales inválidas."); exit()

    srv_device_id = data_usr["device_id"]  # obtiene device_id del servidor
    ruta_priv_srv = f"keys/{srv_device_id}_private_key.pem"  # construye ruta a clave privada

    try:
        priv_srv = descifrar_pem(usuario, password, data_usr, ruta_pem=ruta_priv_srv)  # intenta cargar la clave privada
        print("✓  Clave privada del servidor cargada.")
    except Exception as e:
        print("Error al abrir la clave privada:", e); exit()

    # ── configuración del servidor TCP ───────────────────────
    HOST, PORT = "127.0.0.1", 65432  # dirección y puerto local
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  # crea socket TCP
        s.bind((HOST, PORT))  # vincula IP y puerto
        s.listen()  # pone a escuchar
        print(f"[Servidor] Escuchando en {HOST}:{PORT}")

        while True:  # ciclo infinito de conexión
            conn, addr = s.accept()  # acepta conexión entrante
            with conn:  # gestiona conexión con cliente
                print("[Servidor] Conexión de", addr)

                # ── Fase 1: recibir device-id del cliente ───────────────
                device_id = conn.recv(1024).decode().strip()  # recibe y decodifica el ID
                cli_pub_path = f"keys/{device_id}_public_key.pem"  # ruta a clave pública del cliente
                if not os.path.exists(cli_pub_path):  # si no existe, ignora
                    print("  · Device-ID desconocido"); continue

                with open(cli_pub_path, "rb") as f:  # abre y carga la clave pública
                    cli_pub = serialization.load_pem_public_key(f.read())

                # ── Fase 2: autenticación mutua ─────────────────────────
                nonce_srv = uuid.uuid4().bytes  # genera nonce del servidor
                conn.sendall(nonce_srv)  # envía el nonce al cliente

                firma_cli = conn.recv(256)  # recibe la firma del cliente
                cli_pub.verify(firma_cli, nonce_srv, ec.ECDSA(hashes.SHA256()))  # verifica firma

                nonce_cli = conn.recv(1024)  # recibe nonce del cliente
                firma_srv = priv_srv.sign(nonce_cli, ec.ECDSA(hashes.SHA256()))  # firma con clave del servidor
                conn.sendall(firma_srv)  # envía la firma

                # ── Fase 3: ECDH efímero ───────────────────────────────
                srv_tmp_priv = ec.generate_private_key(ec.SECP256R1())  # clave efímera del servidor
                srv_pub_bytes = srv_tmp_priv.public_key().public_bytes(  # convierte a PEM
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
                conn.sendall(srv_pub_bytes)  # envía clave pública efímera

                cli_pub_bytes = conn.recv(1024)  # recibe la clave efímera del cliente
                cli_tmp_pub = serialization.load_pem_public_key(cli_pub_bytes)  # la convierte a objeto clave pública
                shared = srv_tmp_priv.exchange(ec.ECDH(), cli_tmp_pub)  # realiza ECDH

                aes_key = HKDF(  # deriva la clave AES
                    algorithm=hashes.SHA256(), length=32,
                    salt=None, info=b"handshake data"
                ).derive(shared)
                print("[DEBUG] AES key servidor:", aes_key.hex())  # muestra clave derivada
                aesgcm = AESGCM(aes_key)  # instancia objeto para cifrado
                print("  · Canal seguro establecido.")

                # ── Fase 4: recibir mensaje cifrado y responder ─────────
                try:
                    conn.settimeout(2.0)  # define tiempo límite de espera
                    data = conn.recv(2048)  # recibe datos cifrados
                    nonce_m, ctxt = data[:12], data[12:]  # separa nonce y mensaje

                    print("[DEBUG] Longitud ciphertext recibido:", len(ctxt))
                    print("[DEBUG] Corrompiendo ciphertext para simular ataque...")

                    # --- simula corrupción del mensaje para probar la integridad
                    corrupt_ctxt = bytearray(ctxt)
                    corrupt_ctxt[-1] ^= 0x01  # altera el último byte
                    ctxt = bytes(corrupt_ctxt)

                    msg = aesgcm.decrypt(nonce_m, ctxt, None)  # intenta descifrar
                    print("  · Mensaje:", msg.decode(errors="ignore"))  # imprime mensaje

                    # --- preparar respuesta cifrada ---
                    nonce_rsp = os.urandom(12)  # genera nuevo nonce
                    respuesta = uuid.uuid4().bytes + b"||Hola cliente!!"  # mensaje de respuesta
                    ctxt_rsp = aesgcm.encrypt(nonce_rsp, respuesta, None)  # cifra el mensaje
                    conn.sendall(nonce_rsp + ctxt_rsp)  # envía el paquete cifrado
                    print("  · Respuesta cifrada enviada.")

                except InvalidTag:  # si el mensaje fue modificado y no pasa validación
                    print("  · Error: integridad inválida (tag corrompido)")
                    conn.sendall(b"BAD_TAG")  # envía mensaje de error
                    continue
