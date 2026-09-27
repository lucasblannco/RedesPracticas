"""
practica1.py
Muestra el tiempo de llegada de los primeros 50 paquetes a la interfaz especificada
como argumento y los vuelca a traza nueva con tiempo actual

Autor: Javier Ramos <javier.ramos@uam.es>
2020 EPS-UAM
"""

from rc1_pcap import *
import sys
import binascii
import signal
import argparse
from argparse import RawTextHelpFormatter
import time
import logging

ETH_FRAME_MAX = 1514
PROMISC = 1
NO_PROMISC = 0
TO_MS = 10
TIME_OFFSET = 30 * 60

# Se usa para gestionar cuando el usuario pulsa Cntrl + C
def signal_handler(nsignal, frame):
    logging.info("Control C pulsado")
    if handle:
        #Interrumpe el pcap_loop y hace que devuelva -2
        pcap_breakloop(handle)


# Función que se ejecuta cada vez que llega un paquete nuevo
    # us: en nuestro caso no se usa 
    # header: cabecera pcap del paquete que contiene información relevante (contiene .len, .caplen, .ts.tv_sec y .ts.tv_usec)
    # data: array de bytes que contiene el paquete capturado
def procesa_paquete(us, header, data):
    global num_paquete, primer_timestamp, ultimo_timestamp
    logging.info(
        "Nuevo paquete de {} bytes capturado en el timestamp UNIX {}.{}: ".format(
            header.len, header.ts.tv_sec, header.ts.tv_usec
        )
    )

    # Calculamos el timestamp actual, si es el primer paquete, se marca como el primero, si
    # no es el primero, se actualiza el valor del último en llegar para el cálculo de la diferencia de tiempos
    timestamp = header.ts.tv_sec + header.ts.tv_usec / 1000000.0

    if num_paquete == 0:
        primer_timestamp = timestamp

    ultimo_timestamp = timestamp

    # Se actualiza el valor del número de paquetes recibidos
    num_paquete += 1

    # Si no se especifica --nbytes, mostramos todos los bytes del paquete, si se especifica
    # En caso contrario, se muestra como mucho N bytes
    if args.nbytes is None:
        nbytes = len(data)
    else:
        nbytes = min(args.nbytes, len(data))

    for i in range(0, nbytes, 16):
        # Con el min nos aseguramos que no muestre más de los N bytes especificados
        linea = data[i:min(i + 16, nbytes)]
        # {:02X} Con X lo tenemos en hexadecimal con mayúsuclas y 02 son dos dígitos por byte
        texto = " ".join("{:02X}".format(byte) for byte in linea)
        logging.info(texto)

    #S olo guardamos paquetes si estamos capturando desde interfaz
    if args.interface:
        # Nos aseguramos de que haya al menos 14 bytes y examinamos el byte 13 y 14
        if header.caplen >= 14 and data[12] == 0x08 and data[13] == 0x06:
            # Guardamos en NOIP si coinciden los bytes
            pcap_dump(pdumper_NOIP, header, data)
        else:
            # Guardamos en IP si no coinciden los bytes
            pcap_dump(pdumper_IP, header, data)

if __name__ == "__main__":
    global args, handle, num_paquete
    
    # Creamos el parser que gestiona los argumentos introducidos por terminal.
    parser = argparse.ArgumentParser(
        description="Captura tráfico de una interfaz (o lee de fichero) y muestra la longitud y timestamp de los 50 primeros paquetes",
        formatter_class=RawTextHelpFormatter,
    )
    parser.add_argument(
        "--file", dest="tracefile", default=False, help="Fichero pcap a abrir"
    )
    parser.add_argument(
        "--itf", dest="interface", default=False, help="Interfaz a abrir"
    )
    parser.add_argument(
        "--nbytes",
        dest="nbytes",
        type=int,
        default=None,
        help="Número de bytes a mostrar por paquete",
    )
    parser.add_argument(
        "--debug",
        dest="debug",
        default=False,
        action="store_true",
        help="Activar Debug messages",
    )
    parser.add_argument(
        "--npkts", dest="npkts", type=int, default=-1, help="Número de paquetes a leer"
    )
    
    # Lee los argumentos introducidos por terminal y los guarda en args
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(
            level=logging.DEBUG, format="[%(asctime)s %(levelname)s]\t%(message)s"
        )
    else:
        logging.basicConfig(
            level=logging.INFO, format="[%(asctime)s %(levelname)s]\t%(message)s"
        )
     
    # No permitimos que se introduzcan --file e --itf a la vez o que no se introduzca ninguno 
    if args.tracefile and args.interface:
        logging.error("No se debe usar --file y --itf a la vez")
        parser.print_help()
        sys.exit(-1)

    if args.tracefile is False and args.interface is False:
        logging.error("No se ha especificado interfaz ni fichero")
        parser.print_help()
        sys.exit(-1)

    #Asociamos el signal_handler al Cntrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # Almacena información de error de las funciones pcap_open
    errbuf = bytearray()
    
    handle = None
    num_paquete = 0
    primer_timestamp = None
    ultimo_timestamp = None
    pdumper_NOIP = None
    pdumper_IP = None
    descr = None

    # open_live: abre interfaz: device, snaplen (maximo bytes), promisc (1 o 0), timeout, errbuf
    # open_offline: abre fichero: fname, errbuf
    if args.interface:
        handle = pcap_open_live(args.interface, ETH_FRAME_MAX, PROMISC, TO_MS, errbuf)
    else:
        handle = pcap_open_offline(args.tracefile, errbuf)
        
    if handle is None:
        logging.error("No se ha abierto interfaz o fichero")
        logging.error(errbuf)
        sys.exit(-1)
        

    if args.interface:
        fecha = int(time.time())
        nombre_NOIP = "capturaNOIP.{}.{}.pcap".format(args.interface, fecha)
        nombre_IP = "captura.{}.{}.pcap".format(args.interface, fecha)

        # open_dead: define el tipo/tamaño de las trazas de salida.
        descr = pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX)

        # dump_open: crea los ficheros y devuelve los dumpers.
        pdumper_NOIP = pcap_dump_open(descr, nombre_NOIP)
        pdumper_IP = pcap_dump_open(descr, nombre_IP)

    ret = pcap_loop(handle, args.npkts, procesa_paquete, None)
    if ret == -1:
        logging.error("Error al capturar un paquete")
    elif ret == -2:
        logging.debug("pcap_breakloop() llamado")
    elif ret == 0:
        logging.debug("No mas paquetes o limite superado")
    
    # Estadísticas
    if num_paquete >= 2:
        diferencia = ultimo_timestamp - primer_timestamp
    else:
        diferencia = 0
    logging.info("{} paquetes procesados".format(num_paquete))
    logging.info("Diferencia de tiempo: {} segundos".format(diferencia))
    
    # Cerrar dumpers
    if pdumper_NOIP is not None:
        pcap_dump_close(pdumper_NOIP)

    if pdumper_IP is not None:
        pcap_dump_close(pdumper_IP)

    # Cerramos handle 
    if handle is not None:
        pcap_close(handle)

    if descr is not None:
        pcap_close(descr)
