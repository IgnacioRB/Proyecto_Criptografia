import json, base64, os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag, InvalidSignature

def _derivar_llave(password: bytes, salt: bytes, iterations=100_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)

def cargar_usuario(usuario: str, ruta="usuarios.json") -> dict | None:
    if not os.path.exists(ruta):
        return None
    with open(ruta, "r") as f:
        return json.load(f).get(usuario)

def verificar_password(password: str, usuario_data: dict) -> bool:
    try:
        salt = base64.b64decode(usuario_data["salt"])
        hash_almacenado = base64.b64decode(usuario_data["hashed_password"])
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        kdf.verify(password.encode(), hash_almacenado)
        return True
    except (KeyError, InvalidSignature, ValueError):
        return False


def descifrar_pem(
    usuario: str,
    password: str,
    usuario_data: dict,
    ruta_pem: str | None = None
):
    if ruta_pem is None:
        ruta_pem = f"keys/{usuario}_private_key.pem"

    with open(ruta_pem, "rb") as f:
        contenido = f.read()

    try:
        pem_salt = base64.b64decode(usuario_data["pem_salt"])
        clave    = _derivar_llave(password.encode(), pem_salt)

        if len(contenido) < 13:
            raise InvalidTag

        iv          = contenido[:12]
        ciphertext  = contenido[12:]
        aesgcm      = AESGCM(clave)
        private_raw = aesgcm.decrypt(iv, ciphertext, None)

        return serialization.load_pem_private_key(private_raw, password=None)

    except (InvalidTag, KeyError, ValueError):
        return serialization.load_pem_private_key(contenido, password=None)
