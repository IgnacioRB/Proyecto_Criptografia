# importar módulos necesarios
import os  # para manejar rutas y crear carpetas
import uuid  # para generar un identificador único para el dispositivo
from cryptography.hazmat.primitives.asymmetric import ec  # para generar claves ECC
from cryptography.hazmat.primitives import serialization  # para serializar claves a formato PEM

# crear carpeta llamada 'keys' si no existe, donde se guardarán las claves y archivos generados
key_dir = "keys"
os.makedirs(key_dir, exist_ok=True)

# generar una clave privada usando la curva ECC SECP256R1 (curva de 256 bits)
private_key = ec.generate_private_key(ec.SECP256R1())

# obtener la clave pública correspondiente a la clave privada generada
public_key = private_key.public_key()

# generar un identificador único para el dispositivo (UUID versión 4)
device_id = str(uuid.uuid4())

# construir nombres de archivo para las claves y el archivo de información, usando el device_id
private_key_filename = f"{device_id}_private_key.pem"
public_key_filename = f"{device_id}_public_key.pem"
info_filename = f"{device_id}_info.txt"

# construir la ruta completa para guardar la clave privada en la carpeta 'keys'
private_key_path = os.path.join(key_dir, private_key_filename)

# abrir el archivo en modo binario de escritura y guardar la clave privada serializada en formato PEM
with open(private_key_path, "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,  # codificación PEM (texto base64)
        format=serialization.PrivateFormat.PKCS8,  # formato estándar para claves privadas
        encryption_algorithm=serialization.NoEncryption()  # sin cifrado (en entorno real se debe proteger)
    ))

# construir la ruta completa para guardar la clave pública en la carpeta 'keys'
public_key_path = os.path.join(key_dir, public_key_filename)

# abrir el archivo y guardar la clave pública serializada en formato PEM
with open(public_key_path, "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,  # codificación PEM
        format=serialization.PublicFormat.SubjectPublicKeyInfo  # formato estándar para claves públicas
    ))

# imprimir en consola los datos generados como evidencia
print("Device ID generado:", device_id)
print("Llave privada guardada en:", private_key_path)
print("Llave pública guardada en:", public_key_path)

# construir la ruta para el archivo de información general del dispositivo
info_path = os.path.join(key_dir, "deviceID_info.txt")

# abrir y escribir los detalles del dispositivo en un archivo de texto
with open(info_path, "w") as f:
    f.write(f"Device ID: {device_id}\n")  # escribir ID del dispositivo
    f.write(f"Llave privada: {private_key_path}\n")  # ruta a la clave privada
    f.write(f"Llave pública: {public_key_path}\n")  # ruta a la clave pública
