# -*- coding: utf-8 -*-
'''
    ____             __  _____            __            
   / __ \____  _____/ /_/ ___/___  ____  / /________  __
  / /_/ / __ \/ ___/ __/\__ \/ _ \/ __ \/ __/ ___/ / / /
 / ____/ /_/ / /  / /_ ___/ /  __/ / / / /_/ /  / /_/ / 
/_/    \____/_/   \__//____/\___/_/ /_/\__/_/   \__, /  
                                               /____/   
'''
#######################################################
#    PortSentry.py
#
# PortSentry es una herramienta que permite analizar 
# y monitorizar el tráfico de red, realizar escaneos 
# de puertos en una red y monitorizar eventos de 
# seguridad en tiempo real. Esta herramienta es útil 
# para identificar y analizar actividades sospechosas 
# en la red.
#
#
# 10/18/23 - Changed to Python3 (finally)
#
# Author: Facundo Fernandez 
#
#
#######################################################

import os
import datetime
import subprocess
import netifaces
import requests
import socket
import ssl
import logging

# Directory for storing logs and encrypted files / Directorio para almacenar los registros y archivos cifrados
LOG_DIR = 'logs/'

# Registration configuration / Configuración de registro
logging.basicConfig(filename=os.path.join(LOG_DIR, 'connection_logs.log'), level=logging.INFO, format='%(asctime)s - %(message)s')

def obtener_nombre_usuario():
    return os.getlogin()

def obtener_ip_privada():
    try:
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            if interface != "lo":
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    return addrs[netifaces.AF_INET][0]['addr']
    except Exception:
        return None
    return None

def obtener_informacion_localizacion(direccion_ip):
    try:
        url = f'http://ip-api.com/json/{direccion_ip}'
        respuesta = requests.get(url)
        if respuesta.status_code == 200:
            datos = respuesta.json()
            localizacion = []
            for key in ['country', 'regionName', 'city']:
                if key in datos:
                    localizacion.append(datos[key])
            return ', '.join(localizacion)
    except Exception as e:
        logging.error(f"Error al obtener la informacion de geolocalizacion: {e}")
    return None

def obtener_servicio_por_puerto(puerto):
    # Defining a list of known ports and their associated services / Definir una lista de puertos conocidos y sus servicios asociados
    puertos_conocidos = {
        80: 'HTTP',
        443: 'HTTPS',
        21: 'FTP',
        # Add more ports and services as needed / Agregar más puertos y servicios según sea necesario
    }
    
    # Search for the service associated with the port / Buscar el servicio asociado al puerto
    servicio = puertos_conocidos.get(puerto, 'Desconocido')
    return servicio

def listar_conexiones():
    try:
        result = subprocess.check_output(['netstat', '-tu'])
        conexiones = result.decode('utf-8')
        lineas = conexiones.split('\n')

        # Show current user and IP address / Mostrar usuario y dirección IP actual
        usuario = obtener_nombre_usuario()
        direccion_ip_actual = obtener_ip_privada()
        print(f'Usuario: {usuario}')
        print(f'Dirección IP actual: {direccion_ip_actual}')

        # Display IP addresses with ports in a numbered list / Mostrar las direcciones IP con puertos en una lista numerada
        direcciones_puertos = {}
        index = 1
        for linea in lineas:
            if 'ESTABLISHED' in linea or 'LISTEN' in linea or 'TIME_WAIT' in linea:
                columnas = linea.split()
                direccion_ip = columnas[4].split(':')[0]
                puerto = columnas[4].split(':')[1]
                estado = columnas[5]
                direcciones_puertos[index] = (direccion_ip, puerto, estado)
                print(f'{index}. Direccion IP: {direccion_ip}, Puerto: {puerto}, Estado: {estado}')
                index += 1

        # Allow user to select an IP address or port / Permitir al usuario seleccionar una dirección IP o puerto
        seleccion = input('Seleccione el numero de la direccion IP o puerto que desea obtener informacion detallada (0 para continuar sin cambios, -1 para salir): ')
        seleccion = int(seleccion)

        if seleccion == 0:
            print('Acceso permitido.')
        elif seleccion == -1:
            print('Saliendo...')
        elif seleccion in direcciones_puertos:
            direccion_ip_seleccionada, puerto_seleccionado, estado_seleccionado = direcciones_puertos[seleccion]
            mostrar_informacion_detallada(direccion_ip_seleccionada, puerto_seleccionado, estado_seleccionado)
            # Ask the user if he/she wants to end the process / Preguntar al usuario si desea finalizar el proceso
            finalizar = input('¿Desea cerrar el puerto? (y/n): ')

            if finalizar == 'y':
                # End the process and display a message / Finalizar el proceso y mostrar un mensaje
                finalizar_proceso_por_puerto(puerto_seleccionado)
                print(f'Se finalizo el proceso del puerto {puerto_seleccionado} exitosamente.')

        if seleccion == -1 or finalizar == 'n':
            print('Saliendo...')
        else:
            print('Selección no válida.')

    except subprocess.CalledProcessError:
        print('Error al ejecutar el comando netstat.')

def mostrar_informacion_detallada(direccion_ip, puerto, estado):
    print(f'Informacion detallada para la dirección IP: {direccion_ip}, Puerto: {puerto}, Estado: {estado}')
    
    # Obtain information about the service using the port / Obtener información sobre el servicio que utiliza el puerto
    servicio = obtener_servicio_por_puerto(puerto)
    if servicio:
        print(f'Servicio asociado: {servicio}')
    else:
        print(f'No se pudo determinar el servicio asociado a este puerto.')

    # Verify if TLS/SSL encryption is used / Verificar si se utiliza un cifrado TLS/SSL
    if "https" in puerto:
        cifrado = obtener_cifrado_tls(direccion_ip)
        print(f'Cifrado utilizado: {cifrado}')
        
        if cifrado and "TLS_AES_256_GCM_SHA384" in cifrado[0]:
            print("La conexion es segura (TLS_AES_256_GCM_SHA384).")
        else:
            print("La conexion NO es segura.")

        # Registration information / Registro de información
        logging.info(f'Dirección IP: {direccion_ip}, Puerto: {puerto}, Estado: {estado}, Servicio: {servicio}, Cifrado: {cifrado}')

def obtener_cifrado_tls(direccion_ip):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((direccion_ip, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=direccion_ip) as ssock:
                return ssock.cipher()
    except Exception as e:
        return None

def finalizar_proceso_por_puerto(puerto):
    try:
        proceso_id = obtener_proceso_por_puerto(puerto)
        if proceso_id:
            subprocess.Popen(['kill', '-9', str(proceso_id)])
            print(f'Proceso en el puerto {puerto} finalizado.')
        else:
            print(f'No se pudo encontrar el proceso asociado al puerto {puerto}.')
    except Exception as e:
        print(f'Error al finalizar el proceso en el puerto {puerto}: {e}')

def obtener_proceso_por_puerto(puerto):
    try:
        result = subprocess.check_output(['lsof', '-i', f'tcp:{puerto}'])
        proceso_info = result.decode('utf-8').split('\n')[1]
        proceso_id = proceso_info.split()[1]
        return int(proceso_id)
    except subprocess.CalledProcessError:
        return None
    except (IndexError, ValueError):
        return None

if __name__ == '__main__':
    listar_conexiones()
