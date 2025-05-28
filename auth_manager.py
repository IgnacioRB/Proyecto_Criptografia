# auth_manager.py – funciones para autenticación y carga de claves

# importa librerías necesarias
import json, base64, os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # KDF PBKDF2
from cryptography.hazmat.primitives import hashes, serialization  # hashing y serialización de claves
from cryptography.hazmat.primitives.ciphers.aead import AESGCM     # cifrado AEAD (GCM)
from cryptography.exceptions import InvalidTag, InvalidSignature   # excepciones para errores de autenticación

# función para derivar una clave simétrica AES de 32 bytes (256 bits)
def _derivar_llave(password: bytes, salt: bytes, iterations=100_000) -> bytes:
    """Deriva 32 bytes (AES-256) con PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # usa SHA256 como función hash
        length=32,                  # longitud de clave deseada = 32 bytes
        salt=salt,                  # salt aleatorio
        iterations=iterations,      # número de iteraciones de PBKDF2
    )
    return kdf.derive(password)     # retorna la clave derivada

# carga del archivo usuarios.json y devuelve el diccionario correspondiente al usuario
def cargar_usuario(usuario: str, ruta="usuarios.json") -> dict | None:
    """Devuelve la entrada de *usuarios.json* para «usuario» o None."""
    if not os.path.exists(ruta):   # si el archivo no existe, regresa None
        return None
    with open(ruta, "r") as f:
        return json.load(f).get(usuario)  # carga el JSON y obtiene el valor del usuario

# función para verificar si una contraseña es válida
def verificar_password(password: str, usuario_data: dict) -> bool:
    """Comprueba que el password corresponde al hash y salt almacenados."""
    try:
        # decodifica el salt y el hash almacenado en base64
        salt            = base64.b64decode(usuario_data["salt"])
        hash_almacenado = base64.b64decode(usuario_data["hashed_password"])

        # crea un KDF con los mismos parámetros y verifica
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        kdf.verify(password.encode(), hash_almacenado)  # compara hashes
        return True  # si no lanza excepción, la contraseña es válida

    except (KeyError, InvalidSignature, ValueError):
        # si hay error en el acceso, firma inválida o derivación, retorna False
        return False


# función para descifrar y cargar la clave privada del usuario desde archivo PEM
def descifrar_pem(
    usuario      : str,
    password     : str,
    usuario_data : dict,
    ruta_pem     : str | None = None
):
    """
    Devuelve un objeto Crypto PrivateKey.
    – Si el archivo está cifrado con AES-GCM (formato IV||ciphertext) lo descifra.
    – Si no, asume PEM plano y lo carga directamente.
    """
    
    # si no se especifica una ruta para la clave PEM, se construye la ruta por defecto
    if ruta_pem is None:
        ruta_pem = f"keys/{usuario}_private_key.pem"

    # abre y lee el contenido del archivo PEM (clave cifrada o no)
    with open(ruta_pem, "rb") as f:
        contenido = f.read()

    # ── intentar descifrar como clave cifrada ──────────────────────────────
    try:
        # obtiene el salt usado para derivar la clave AES desde usuario_data
        pem_salt = base64.b64decode(usuario_data["pem_salt"])
        # deriva la clave simétrica AES desde la contraseña y el salt
        clave    = _derivar_llave(password.encode(), pem_salt)

        # verifica si el contenido es suficientemente largo para tener un IV y ciphertext
        if len(contenido) < 13:
            raise InvalidTag  # mínimo 12 bytes de IV + 1 byte de ciphertext

        # separa el IV y el ciphertext
        iv         = contenido[:12]
        ciphertext = contenido[12:]

        # crea un objeto AES-GCM con la clave derivada
        aesgcm = AESGCM(clave)

        # descifra el contenido
        private_raw = aesgcm.decrypt(iv, ciphertext, None)

        # carga la clave privada desde el PEM descifrado
        return serialization.load_pem_private_key(private_raw, password=None)

    except (InvalidTag, KeyError, ValueError):
        # si el archivo no está cifrado o hay error, se intenta cargar directamente como PEM plano
        return serialization.load_pem_private_key(contenido, password=None)
