import os
import logging
import datetime
import socket
import ipaddress
import stat
import requests 
from user_agents import parse
import hashlib
import uuid
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


def obtener_direccion_ip():
    try:
        direccion_ip = socket.gethostbyname(socket.gethostname())
        return direccion_ip
    except socket.gaierror:
        return None

# Lista blanca de direcciones IP autorizadas
direcciones_ip_permitidas = {
    'usuario1': ['192.168.1.0/24'],
    'usuario2': ['192.168.1.101']
}

def obtener_informacion_localizacion(direccion_ip):
    try:
        url = f'http://ip-api.com/json/{direccion_ip}'
        respuesta = requests.get(url)
        datos = respuesta.json()
        return datos
    except requests.exceptions.RequestException:
        return None

def verificar_direccion_ip(usuario):
    direccion_ip_actual = obtener_direccion_ip()
    if direccion_ip_actual is not None:
        if usuario in direcciones_ip_permitidas:
            direcciones_permitidas = direcciones_ip_permitidas[usuario]
            for direccion in direcciones_permitidas:
                if ipaddress.ip_address(direccion_ip_actual) in ipaddress.ip_network(direccion):
                    return True
        else:
            datos_localizacion = obtener_informacion_localizacion(direccion_ip_actual)
            if datos_localizacion is not None:
                guardar_registro_no_autorizado(usuario, direccion_ip_actual, datos_localizacion)
    return False

def guardar_registro_no_autorizado(usuario, direccion_ip, datos_localizacion):
    mensaje = f'Intento no autorizado - Usuario: {usuario} - Dirección IP: {direccion_ip} - Localización: {datos_localizacion}'
    logging.warning(mensaje)
    
    # Guardar el registro en un archivo de texto
    try:
        with open('registros.txt', 'a') as archivo:
            archivo.write(mensaje + '\n')
    except IOError:
        logging.error('Error al guardar el registro en el archivo')

def registrar_actividad(usuario, accion, direccion_ip, datos_localizacion):
    fecha_hora = datetime.datetime.now()
    mensaje = f'[{fecha_hora}] - Usuario: {usuario} - Acción: {accion} - Dirección IP: {direccion_ip} - Localización: {datos_localizacion}'
    logging.info(mensaje)
    
    # Guardar el registro en un archivo de texto
    try:
        with open('registros.txt', 'a') as archivo:
            archivo.write(mensaje + '\n')
    except IOError:
        logging.error('Error al guardar el registro en el archivo')


def cifrar_archivo_clave(clave_privada, ruta, contrasena):
    # Generar una clave de cifrado basada en la contraseña
    clave_cifrado = Fernet.generate_key()
    fernet = Fernet(clave_cifrado)

    try:
        # Leer el contenido del archivo de clave privada
        with open(ruta, 'rb') as archivo:
            contenido = archivo.read()

        # Cifrar el contenido utilizando la clave de cifrado
        contenido_cifrado = fernet.encrypt(contenido)

        # Guardar el contenido cifrado en un nuevo archivo
        ruta_cifrado = ruta + '.enc'
        with open(ruta_cifrado, 'wb') as archivo_cifrado:
            archivo_cifrado.write(contenido_cifrado)

        # Guardar la clave de cifrado en un archivo separado
        ruta_clave = ruta + '.key'
        with open(ruta_clave, 'wb') as archivo_clave:
            archivo_clave.write(clave_cifrado)

        logging.info('El archivo de clave privada se ha cifrado correctamente.')
        logging.info('Se ha generado un archivo cifrado: ' + ruta_cifrado)
        logging.info('Se ha generado un archivo de clave: ' + ruta_clave)

    except IOError:
        logging.error('Error al leer o escribir el archivo de clave privada.')

def almacenar_clave_privada(clave_privada, ruta):
    try:
        # Guardar la clave privada en un archivo temporal
        ruta_temporal = ruta + '.tmp'
        with open(ruta_temporal, 'wb') as archivo:
            archivo.write(clave_privada)

        # Establecer los permisos de archivo de manera segura
        os.chmod(ruta_temporal, stat.S_IRUSR | stat.S_IWUSR)

        # Renombrar el archivo temporal al nombre deseado
        os.rename(ruta_temporal, ruta)

        logging.info('Se almacenó de forma segura la clave privada RSA en ' + ruta)

    except IOError:
        logging.error('Error al almacenar la clave privada.')


def generar_clave_privada():
    # Generar una nueva clave privada RSA con un tamaño de 2048 bits
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serializar la clave privada en formato PEM
    clave_privada_pem = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Guardar la clave privada en un archivo
    ruta_clave_privada = 'clave_privada.pem'
    with open(ruta_clave_privada, 'wb') as archivo_clave_privada:
        archivo_clave_privada.write(clave_privada_pem)

    logging.info('Se generó una nueva clave privada RSA')
    logging.info('La clave privada se ha guardado en el archivo: ' + ruta_clave_privada)

def obtener_agente_usuario():
    agente_usuario = input("Ingresa el agente de usuario del cliente: ")
    return parse(agente_usuario)

def obtener_informacion_red():
    informacion_red = {}

    # Obtener la dirección IP del host local
    informacion_red['direccion_ip'] = socket.gethostbyname(socket.gethostname())

    # Obtener el nombre del host local
    informacion_red['nombre_host'] = socket.gethostname()

    # Obtener la dirección MAC de la interfaz de red activa (requiere Windows)
    if 'Windows' in socket.gethostname():
        informacion_red['direccion_mac'] = ':'.join(['{:02X}'.format((uuid.getnode() >> i) & 0xFF) for i in range(0, 48, 8)])
    else:
        informacion_red['direccion_mac'] = 'No disponible en este sistema operativo'

    # Obtener la lista de interfaces de red disponibles
    interfaces = socket.if_nameindex()
    informacion_red['interfaces'] = [interface[1] for interface in interfaces]

    return informacion_red

def obtener_fecha_hora_actual():
    return datetime.datetime.now()

def main():
    # Obtener usuario, dirección IP y otros datos relevantes
    usuario = 'usuario1'
    direccion_ip = obtener_direccion_ip()
    agente_usuario = obtener_agente_usuario()
    informacion_red = obtener_informacion_red()

    # Verificar la dirección IP y realizar las acciones correspondientes
    if verificar_direccion_ip(usuario):
        accion = 'Acceso autorizado'
        datos_localizacion = obtener_informacion_localizacion(direccion_ip)
        registrar_actividad(usuario, accion, direccion_ip, datos_localizacion)
        # Resto del código para realizar acciones permitidas
    else:
        accion = 'Intento no autorizado'
        datos_localizacion = obtener_informacion_localizacion(direccion_ip)
        registrar_actividad(usuario, accion, direccion_ip, datos_localizacion)
        # Resto del código para manejar intentos no autorizados

if __name__ == '__main__':
    main()

def generar_clave_privada():
    # Generar una nueva clave privada RSA segura
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Serializar la clave privada en formato PEM
    clave_privada_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    
    # Guardar la clave privada en un archivo
    ruta_archivo = 'ruta/clave_privada.pem'
    with open(ruta_archivo, 'wb') as archivo:
        archivo.write(clave_privada_pem)
    
    logging.info(f'Se generó una nueva clave privada RSA y se guardó en {ruta_archivo}')

def almacenar_clave_privada(clave_privada, ruta):
    # Serializar la clave privada en formato PEM
    clave_privada_pem = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Guardar la clave privada en un archivo
    with open(ruta, 'wb') as archivo:
        archivo.write(clave_privada_pem)
    
    # Establecer permisos restrictivos para el archivo de clave privada
    os.chmod(ruta, stat.S_IRUSR | stat.S_IWUSR)
    
    logging.info(f'Se almacenó de forma segura la clave privada RSA en {ruta}')

def registrar_actividad(usuario, accion, direccion_ip):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    mensaje = f'[{timestamp}] - Usuario: {usuario} - Acción: {accion} - Dirección IP: {direccion_ip}'
    guardar_registro(mensaje)
    logging.info(mensaje)

def guardar_registro(mensaje):
    ruta_archivo = 'ruta/registro_actividades.log'
    with open(ruta_archivo, 'a') as archivo:
        archivo.write(mensaje + '\n')

def cifrar_archivo_clave(clave_privada, ruta, contrasena):
    # Serializar la clave privada en formato PEM
    clave_privada_pem = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Generar una clave de cifrado a partir de la contraseña
    salt = os.urandom(16)
    kdf = default_backend().key_derivation_functions.pbkdf2.PBKDF2HMAC(
        salt=salt,
        length=32,
        iterations=100000,
        algorithm=hashes.SHA256()
    )
    clave_cifrada = kdf.derive(contrasena.encode())
    
    # Generar un vector de inicialización (IV) aleatorio
    iv = os.urandom(16)
    
    # Cifrar los datos de la clave privada
    cifrador = Cipher(
        algorithms.AES(clave_cifrada),
        modes.CBC(iv),
        backend=default_backend()
    ).encryptor()
    clave_privada_cifrada = cifrador.update(clave_privada_pem) + cifrador.finalize()
    
    # Calcular el hash de la clave cifrada
    hash_clave = hashlib.sha256(clave_cifrada).digest()
    
    # Guardar los datos cifrados en el archivo
    datos_cifrados = salt + iv + clave_privada_cifrada + hash_clave
    with open(ruta, 'wb') as archivo:
        archivo.write(datos_cifrados)
    
    logging.info('Se cifró el archivo de clave privada')

if __name__ == '__main__':
    logging.basicConfig(filename='registro.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    usuario_actual = 'usuario1'  # Nombre del usuario actual

    if verificar_direccion_ip(usuario_actual):
        # Permitir que el usuario utilice la clave privada RSA
        generar_clave_privada()
        almacenar_clave_privada('clave_privada', 'ruta/clave_privada.pem')
        registrar_actividad(usuario_actual, 'Acceso a la clave privada', obtener_direccion_ip())
        
        # Cifrar el archivo de clave privada
        contrasena = 'contrasena_secreta'
        cifrar_archivo_clave('clave_privada', 'ruta/clave_privada_cifrada.pem', contrasena)
        
    else:
        # Denegar el acceso a la clave privada RSA
        registrar_actividad(usuario_actual, 'Intento de acceso denegado', obtener_direccion_ip())
        print('Acceso denegado. Dirección IP no permitida para el usuario actual.')
