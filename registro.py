# registro.py  ·  crea usuario, claves ECC y guarda device_id (manual u opcional)

# importa librerías estándar necesarias
import os, json, base64, uuid
from getpass import getpass  # para ocultar la contraseña al ingresarla

# importa funciones criptográficas necesarias
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# define la función principal para crear un nuevo usuario
def crear_usuario(usuario: str, contrasena: str, device_id: str | None = None,
                  reutilizar_claves=True) -> str:
    """
    Crea un nuevo usuario con claves ECC. Si reutilizar_claves=True y ya existen claves
    asociadas al device_id, se reutilizan en lugar de generar nuevas.
    """
    
    # ─────────────────────────────────────────────
    # 1) Device-ID: recibido manualmente o generado automáticamente
    # ─────────────────────────────────────────────
    did = device_id.strip() if device_id else str(uuid.uuid4())

    # ─────────────────────────────────────────────
    # 2) Verifica si ya existen claves asociadas al device_id
    # ─────────────────────────────────────────────
    private_src = f"keys/{did}_private_key.pem"
    public_src  = f"keys/{did}_public_key.pem"

    # determina si se deben reutilizar las claves ya existentes
    usar_existentes = (
        reutilizar_claves and
        os.path.exists(private_src) and
        os.path.exists(public_src)
    )

    if usar_existentes:
        # ----- reutiliza el par de claves existente emitido por la RA -----
        with open(private_src, "rb") as f:
            private_bytes_origen = f.read()  # lee la clave privada en bytes

        with open(public_src, "rb") as f:
            public_bytes = f.read()  # lee la clave pública en bytes

        print(f"[INFO] Reutilizando claves del dispositivo {did}")

    else:
        # ----- genera un nuevo par de claves ECC -----
        priv_key = ec.generate_private_key(ec.SECP256R1())  # clave privada ECC

        # serializa la clave pública a PEM
        public_bytes = priv_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # serializa la clave privada sin cifrado para después cifrarla
        private_bytes_origen = priv_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

        print("[INFO] Generando nuevo par de claves (no había claves previas)")

    # ─────────────────────────────────────────────
    # 3) Cifra la clave privada usando AES-GCM y PBKDF2-HMAC
    # ─────────────────────────────────────────────
    
    # genera dos valores aleatorios de 16 bytes para las sales
    salt_pw, salt_pem = os.urandom(16), os.urandom(16)

    # deriva un hash de contraseña para almacenamiento seguro (para login)
    hash_pw = PBKDF2HMAC(hashes.SHA256(), 32, salt_pw, 100_000)\
                .derive(contrasena.encode())

    # deriva la clave simétrica para cifrar la clave privada PEM
    key_pem = PBKDF2HMAC(hashes.SHA256(), 32, salt_pem, 100_000)\
                .derive(contrasena.encode())

    # genera un IV de 12 bytes (nonce) para AES-GCM
    iv = os.urandom(12)

    # cifra la clave privada sin cifrar con AES-GCM
    ciphertext = AESGCM(key_pem).encrypt(iv, private_bytes_origen, None)

    # ─────────────────────────────────────────────
    # 4) Guarda las claves cifradas y públicas en archivos
    # ─────────────────────────────────────────────
    os.makedirs("keys", exist_ok=True)  # crea el directorio si no existe

    priv_path = f"keys/{usuario}_private_key.pem"  # ruta para clave privada cifrada
    pub_path  = f"keys/{usuario}_public_key.pem"   # ruta para clave pública

    # guarda la clave privada cifrada junto con el IV
    with open(priv_path, "wb") as f:
        f.write(iv + ciphertext)

    # guarda la clave pública
    with open(pub_path, "wb") as f:
        f.write(public_bytes)

    # ─────────────────────────────────────────────
    # 5) Actualiza el archivo usuarios.json
    # ─────────────────────────────────────────────

    usuarios = {}  # inicializa el diccionario de usuarios

    # si ya existe el archivo, lo carga
    if os.path.exists("usuarios.json"):
        with open("usuarios.json", "r") as f:
            usuarios = json.load(f)

    # guarda la nueva entrada para el usuario actual
    usuarios[usuario] = {
        "device_id":       did,
        "salt":            base64.b64encode(salt_pw).decode(),         # base64 del salt del hash
        "hashed_password": base64.b64encode(hash_pw).decode(),         # base64 del hash
        "pem_salt":        base64.b64encode(salt_pem).decode(),        # base64 del salt de cifrado
    }

    # escribe de vuelta el archivo JSON actualizado
    with open("usuarios.json", "w") as f:
        json.dump(usuarios, f, indent=4)

    # regresa un resumen informativo con paths generados
    return (
        f"Usuario «{usuario}» vinculado al Device-ID {did}\n"
        f"Clave privada cifrada → {priv_path}\n"
        f"Clave pública         → {pub_path}"
    )


# ──────────────────────────── EJECUCIÓN DIRECTA ────────────────────────────
if __name__ == "__main__":
    # solicita el nombre de usuario desde consola
    usr  = input("Nombre de usuario: ").strip()

    # solicita la contraseña en modo oculto
    pwd  = getpass("Contraseña: ")

    # permite ingresar un device-id ya existente o generar uno nuevo
    did_in = input("(Opcional) Device-ID existente (Enter para generar): ").strip() or None

    # llama a la función crear_usuario y muestra el resultado
    print(crear_usuario(usr, pwd, did_in))
