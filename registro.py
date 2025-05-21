import os, json, base64, uuid
from getpass import getpass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def crear_usuario(usuario: str, contrasena: str, device_id: str | None = None,
                  reutilizar_claves=True) -> str:
    did = device_id.strip() if device_id else str(uuid.uuid4())

    private_src = f"keys/{did}_private_key.pem"
    public_src  = f"keys/{did}_public_key.pem"

    usar_existentes = (
        reutilizar_claves and
        os.path.exists(private_src) and
        os.path.exists(public_src)
    )

    if usar_existentes:
        with open(private_src, "rb") as f:
            private_bytes_origen = f.read()

        with open(public_src, "rb") as f:
            public_bytes = f.read()

        print(f"[INFO] Reutilizando claves del dispositivo {did}")

    else:
        priv_key = ec.generate_private_key(ec.SECP256R1())
        public_bytes = priv_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_bytes_origen = priv_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        print("[INFO] Generando nuevo par de claves (no había claves previas)")

    salt_pw, salt_pem = os.urandom(16), os.urandom(16)
    hash_pw = PBKDF2HMAC(hashes.SHA256(), 32, salt_pw, 100_000)\
                .derive(contrasena.encode())
    key_pem = PBKDF2HMAC(hashes.SHA256(), 32, salt_pem, 100_000)\
                .derive(contrasena.encode())

    iv = os.urandom(12)
    ciphertext = AESGCM(key_pem).encrypt(iv, private_bytes_origen, None)

    os.makedirs("keys", exist_ok=True)
    priv_path = f"keys/{usuario}_private_key.pem"
    pub_path  = f"keys/{usuario}_public_key.pem"

    with open(priv_path, "wb") as f:
        f.write(iv + ciphertext)

    with open(pub_path, "wb") as f:
        f.write(public_bytes)

    return "Usuario creado, claves guardadas, aún falta actualizar usuarios.json"


if __name__ == "__main__":
    usr  = input("Nombre de usuario: ").strip()
    pwd  = getpass("Contraseña: ")

    did_in = input("(Opcional) Device-ID existente (Enter para generar): ").strip() or None
    print(crear_usuario(usr, pwd, did_in))
