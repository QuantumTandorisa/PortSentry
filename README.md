PortSentry es una herramienta que permite analizar y monitorear el tráfico de red, realizar escaneos de puertos en una red y supervisar eventos de seguridad en tiempo real. Esta herramienta es útil para identificar y analizar actividades sospechosas en la red.

## Características

- Monitoreo de conexiones de red en tiempo real.
- Identificación de direcciones IP, puertos y estados de conexión.
- Análisis de servicios asociados a puertos.
- Verificación de conexiones seguras a través de cifrado TLS/SSL.
- Finalización segura de procesos en puertos específicos.

## Requisitos

- Python 3.x
- Bibliotecas requeridas, que puedes instalar ejecutando `pip install -r requirements.txt`.

## Uso

- Clona este repositorio en tu sistema.
- Crea un entorno virtual e instala las dependencias del proyecto.
- Ejecuta la aplicación con Python 3.9 o superior:  `PortSentry.py`.

La herramienta mostrará una lista de conexiones de red en tiempo real.
Selecciona una dirección IP o puerto para obtener información detallada.
Puedes cerrar un puerto específico si lo deseas.

## Configuración

Puedes personalizar la configuración de registro en el archivo PortSentry.py.
Los registros se almacenan en el directorio "logs" por defecto.
