# IoTHunter
# Detector de Dispositivos IoT Vulnerables

## Descripción
El "Detector de Dispositivos IoT Vulnerables" es una herramienta escrita en Python que permite identificar dispositivos IoT dentro de una red local y evaluar algunas de las vulnerabilidades más comunes asociadas a ellos.

## Prerrequisitos
- **Python 3.x**
- **nmap** instalado en tu sistema.
- **Librerías de Python**: `nmap`, `scapy`

### Instalación de librerías
Puedes instalar las librerías necesarias usando `pip`:
```bash
pip install python-nmap scapy
```

###Uso
Ejecutar el programa
```b
python nombre_del_script.py
```
Por defecto, la herramienta escaneará la red 192.168.1.0/24.

Especificar un rango IP diferente
```bash
python nombre_del_script.py -r 192.168.0.0/24
```
Cambia 192.168.0.0/24 al rango deseado.

Detección de Dispositivos en la Red: La herramienta primero identifica todos los dispositivos activos en la red local mediante el protocolo ARP.
Identificación de Dispositivos IoT: A continuación, se escanea cada dispositivo identificado para determinar si tiene puertos abiertos que son comunes en dispositivos IoT. La identificación se basa en una lista predefinida de puertos que son típicos de dispositivos IoT.

###Uso
###Funcionamiento
#1: Detección de Dispositivos en la Red: La herramienta primero identifica todos los dispositivos activos en la red local mediante el protocolo ARP.
#2: Identificación de Dispositivos IoT: A continuación, se escanea cada dispositivo identificado para determinar si tiene puertos abiertos que son comunes en dispositivos IoT. La identificación se basa en una lista predefinida de puertos que son típicos de dispositivos IoT.
#3: Evaluación de Vulnerabilidades: Después de identificar un dispositivo IoT, la herramienta procede a escanear todos sus puertos abiertos. Luego, compara estos puertos con una lista de vulnerabilidades conocidas para determinar si el dispositivo está potencialmente en riesgo.
#4: Reporte: Finalmente, la herramienta muestra un resumen de los dispositivos IoT detectados y las vulnerabilidades encontradas.

###Notas
Responsabilidad: Úsalo solo en redes en las que tengas permiso para hacerlo. El escaneo no autorizado es ilegal y no ético.
Expansibilidad: La herramienta se basa en listas predefinidas de puertos asociados con dispositivos IoT y vulnerabilidades. Siempre puedes expandir y actualizar estas listas según tus necesidades y conocimientos.
###Contribuciones
Las contribuciones al proyecto son bienvenidas. Si identificas una mejora o una nueva característica que podría enriquecer la herramienta, no dudes en hacer un fork del repositorio y enviar un pull request.
