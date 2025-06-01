# Protocolo de Comunicación Seguro para un dispositivo con bajos recursos computacionales

Equipo:
- González Gutierrez Adrián Sebastían
- Ornelas Garduño Alexis Johan
- Ramírez Bartolo Ignacio
- Ramírez Santamaría Carlos Isaac

Este proyecto simula un reloj inteligente (smartwatch) con bajos recursos computacionales que se comunica con un servidor confiable usando un protocolo de seguridad completo creado por el equipo que plantea cumplir con las siguiente propiedades: autenticación, confidencialidad e integridad.

La interfaz web representa el smartwatch, y todo el backend está hecho en Python. Se implementan prácticas reales de criptografía, usando algoritmos modernos y seguros como bibliotecas estandarizadas.

En este proyecto se demuestra:

- **Autenticación Mutua**  
Ambos (cliente y servidor) prueban que son quienes dicen ser, firmando nonces únicos con ECDSA.

- **Confidencialidad**  
Toda contraseña o dato enviado (como el pulso o pasos) viaja cifrado con AES-GCM.

- **Integridad**  
Si alguien modifica el mensaje, el servidor lo detecta de inmediato y se muestra un error (InvalidTag).

## Archivos principales

- `api.py` → Backend Flask que sirve como puente entre el back-end (el código de Python) y front-end (index.html).
- `auth_manager.py` → Verifica contraseñas, descifra claves y deriva llaves.
- `registro.py` → Registra usuarios y genera claves ECC cifradas.
- `server.py` → Servidor con autenticación mutua, ECDH y canal seguro.
- `cliente.py` → Simulación de Cliente que realiza la autenticación mutua y prueba el canal seguro.
- `Front-End/index.html` → Simulación de smartwatch en el navegador.

También incluye el directorio `keys/` donde se guardan las llaves de los usuarios y el archivo `usuarios.json` con sus datos.

## Credenciales
Para el cliente:
- Usuario: ignacio
- Contraseña: contrasena123

Para el servidor:
- Usuario: servidor
- Contraseña: servidor123

## ¿Qué se necesita para correrlo?

Debes tener instalado lo siguiente:

- **Python 3.10+**
- **Librerías**: `cryptography`, `flask`, `flask-cors` (si no se tienen instaladas)
- Un navegador web moderno (para abrir el smartwatch)
- Desactivar el firewall para las pruebas

### Para instalar las dependencias:
```bash
pip install cryptography flask flask-cors
