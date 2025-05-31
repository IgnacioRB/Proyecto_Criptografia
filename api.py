# api.py  – conexión entre el front-end y el back-end
from flask import Flask, request, jsonify # importa la clase Flask y funciones para manejar peticiones y respuestas en JSON
from flask_cors import CORS # permite peticiones entre diferentes dominios (necesario para que el frontend pueda comunicarse con el backend)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # importa el algoritmo de cifrado autenticado AES-GCM
from auth_manager import cargar_usuario, verificar_password, descifrar_pem # importa funciones del archivo auth_manager.py para cargar usuarios y verificar contraseñas
from server import autenticar_dispositivo_para_api # importa la función de autenticación del servidor definida en server.py
import os, base64 # importa librerías del sistema y codificación base64 para manejar datos binarios
from cryptography.exceptions import InvalidTag # importa la excepción que se lanza cuando la integridad del mensaje es inválida

# inicializa la aplicación Flask
app = Flask(__name__)

# habilita CORS para permitir peticiones desde el frontend (como index.html en otro puerto)
CORS(app)

# genera una clave AES aleatoria de 256 bits para uso general (rutas como /pulso y /pasos)
clave_aes = AESGCM.generate_key(bit_length=256)

# crea un objeto AESGCM con la clave generada
aesgcm = AESGCM(clave_aes)

# define la ruta /login para autenticar al usuario
@app.route("/login", methods=["POST"])
def login():
    # recibe los datos en formato JSON desde el frontend
    datos = request.get_json()

    # extrae el nombre de usuario
    usuario = datos.get("usuario")

    # decodifica el nonce recibido en base64
    nonce = base64.b64decode(datos.get("nonce"))

    # decodifica la contraseña cifrada recibida
    cifrado = base64.b64decode(datos.get("cifrado"))

    try:
        # carga los datos del usuario desde usuarios.json
        usuario_data = cargar_usuario(usuario)

        # si no se encuentra el usuario, responde con error
        if not usuario_data:
            return jsonify({"success": False, "error": "Usuario no encontrado"}), 200

        # define una clave fija en hexadecimal para el login (simulación)
        clave_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

        # convierte la clave hexadecimal a binario
        clave_bin = bytes.fromhex(clave_hex)

        # instancia el objeto AESGCM con la clave fija
        aesgcm = AESGCM(clave_bin)

        # convierte el mensaje cifrado en un arreglo de bytes para simular corrupción
        #cifrado_corrupto = bytearray(cifrado)

        # altera el último byte del mensaje cifrado
        #cifrado_corrupto[-1] ^= 0x01

        # lo convierte de nuevo a bytes
        #cifrado = bytes(cifrado_corrupto)

        # intenta descifrar la contraseña
        try:
            contrasena = aesgcm.decrypt(nonce, cifrado, None).decode()
        except InvalidTag:
            # si ocurre un error de integridad, imprime en consola y responde
            print("[ERROR INTEGRIDAD] El ciphertext fue alterado.")
            return jsonify({"success": False, "error": "InvalidTag"}), 200

        # verifica que la contraseña ingresada coincida con el hash del usuario
        if not verificar_password(contrasena, usuario_data):
            return jsonify({"success": False, "error": "Contraseña incorrecta"}), 200

        # intenta descifrar la llave privada para verificar que la contraseña sea válida
        try:
            descifrar_pem(usuario, contrasena, usuario_data)
        except Exception as e:
            return jsonify({"success": False, "error": "Contraseña incorrecta"}), 200

        # obtiene el device_id del usuario
        device_id = usuario_data["device_id"]

        # realiza autenticación simulada con la función del servidor
        resultado = autenticar_dispositivo_para_api(device_id)

        # si hubo un error en la autenticación, lo reporta
        if "error" in resultado:
            return jsonify({"success": False, "error": resultado["error"]}), 500

        # imprime los datos criptográficos en consola para demostrar autenticación mutua y confidencialidad
        print("[LOGIN] Autenticación mutua completada")
        print("Contraseña cifrada recibida:", base64.b64encode(cifrado).decode())
        print("Device ID:", device_id)
        print("Nonce del servidor:", resultado["nonce_servidor"])
        print("Firma enviada (simulada):", resultado["firma_cliente"])
        print("Nonce del cliente recibido:", resultado["nonce_cliente"])
        print("Clave AES derivada (ECDH + HKDF):", resultado["clave_aes"])
        print("Autenticación mutua completada correctamente")

        # responde al frontend que todo fue exitoso
        return jsonify({"success": True})

    # si ocurre cualquier otro error, lo reporta
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# define la ruta /pulso para cifrar y validar un mensaje simulado de salud
@app.route("/pulso", methods=["POST"])
def cifrar_pulso():
    try:
        # obtiene los datos enviados por el frontend
        data = request.get_json()

        # obtiene el mensaje que se desea cifrar
        mensaje = data.get("mensaje", "")

        # si no se envió mensaje, retorna error
        if not mensaje:
            return jsonify({"error": "No se proporcionó mensaje"}), 400

        # genera un nonce aleatorio de 12 bytes
        nonce = os.urandom(12)

        # cifra el mensaje usando AES-GCM
        cifrado = aesgcm.encrypt(nonce, mensaje.encode(), None)

        # convierte el mensaje cifrado en arreglo para simular corrupción
        #cifrado_corrupto = bytearray(cifrado)

        # altera el último byte
        #cifrado_corrupto[-1] ^= 0x01

        # lo convierte de nuevo a bytes
        #cifrado = bytes(cifrado_corrupto)

        # intenta descifrar el mensaje para comprobar la integridad
        try:
            aesgcm.decrypt(nonce, cifrado, None)
        except InvalidTag:
            # si ocurre error de integridad, lo reporta en consola y responde
            print("[ERROR INTEGRIDAD] Mensaje alterado")
            return jsonify({"error": "InvalidTag"}), 200

        # imprime los datos criptográficos en consola para demostración
        print("[PULSO] Texto original:", mensaje)
        print("[PULSO] Nonce:", nonce.hex())
        print("[PULSO] Cifrado (base64):", base64.b64encode(cifrado).decode())
        print("[PULSO] Clave AES (base64):", base64.b64encode(clave_aes).decode())

        # responde con metadatos de cifrado (no se manda texto cifrado real)
        return jsonify({
            "mensaje_original": mensaje,
            "algoritmo": "AES-GCM",
            "mensaje_cifrado": "✓",
            "nonce": "✓",
            "longitud_clave": len(clave_aes) * 8
        })

    except InvalidTag:
        # error de integridad capturado fuera del try interno
        print("[ERROR] Integridad comprometida: el mensaje fue alterado")
        return jsonify({"error": "InvalidTag"}), 200

    # si ocurre otro tipo de error, lo reporta
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# define la ruta /pasos para probar otro mensaje cifrado con validación de integridad
@app.route("/pasos", methods=["POST"])
def cifrar_pasos():
    try:
        # obtiene los datos en formato JSON
        data = request.get_json()

        # obtiene el mensaje enviado
        mensaje = data.get("mensaje", "")

        # si no se envió mensaje, retorna error
        if not mensaje:
            return jsonify({"error": "No se proporcionó mensaje"}), 400

        # genera un nonce aleatorio de 12 bytes
        nonce = os.urandom(12)

        # cifra el mensaje usando AES-GCM
        cifrado = aesgcm.encrypt(nonce, mensaje.encode(), None)

        # altera el mensaje cifrado para simular corrupción
        #cifrado_corrupto = bytearray(cifrado)
        #cifrado_corrupto[-1] ^= 0x01
        #cifrado = bytes(cifrado_corrupto)

        # imprime los datos cifrados en consola para demostrar confidencialidad
        print("[PASOS] Texto original:", mensaje)
        print("[PASOS] Nonce:", nonce.hex())
        print("[PASOS] Cifrado (base64):", base64.b64encode(cifrado).decode())
        print("[PASOS] Clave AES (base64):", base64.b64encode(clave_aes).decode())

        # intenta descifrar para verificar la integridad
        try:
            mensaje_descifrado = aesgcm.decrypt(nonce, cifrado, None).decode()
        except InvalidTag:
            # si el tag es inválido, significa que el mensaje fue modificado
            print("[ERROR INTEGRIDAD] El mensaje fue alterado.")
            return jsonify({"success": False, "error": "InvalidTag"}), 200

        # responde con datos correctos si no hubo corrupción
        return jsonify({
            "mensaje_original": mensaje_descifrado,
            "algoritmo": "AES-GCM",
            "mensaje_cifrado": "✓",
            "nonce": "✓",
            "longitud_clave": len(clave_aes) * 8
        })

    # captura errores generales
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ejecuta la aplicación Flask en localhost:5000
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
