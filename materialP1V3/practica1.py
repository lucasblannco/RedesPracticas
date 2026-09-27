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


def signal_handler(nsignal, frame):
    logging.info("Control C pulsado")
    if handle:
        pcap_breakloop(handle)


def procesa_paquete(us, header, data):
    global num_paquete, primer_timestamp, ultimo_timestamp
    logging.info(
        "Nuevo paquete de {} bytes capturado en el timestamp UNIX {}.{}: ".format(
            header.len, header.ts.tv_sec, header.ts.tv_usec
        )
    )

    timestamp = header.ts.tv_sec + header.ts.tv_usec / 1000000.0

    if num_paquete == 0:
        primer_timestamp = timestamp

    ultimo_timestamp = timestamp


    num_paquete += 1
    # TODO imprimir los N primeros bytes
    # Mostrar N primeros bytes
    if args.nbytes is None:
        nbytes = len(data)
    else:
        nbytes = min(args.nbytes, len(data))

    for i in range(0, nbytes, 16):
        linea = data[i:i + 16]
        texto = " ".join("{:02X}".format(byte) for byte in linea)
        logging.info(texto)

    # Escribir el tráfico al fichero de captura con el offset temporal
    # Ver si se van a escribir en NOIP o IP
    if args.interface:
        if header.caplen >= 14 and data[12] == 0x08 and data[13] == 0x06:
            pcap_dump(pdumper_NOIP, header, data)
        else:
            pcap_dump(pdumper_IP, header, data)

if __name__ == "__main__":
    global args, handle, num_paquete
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
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(
            level=logging.DEBUG, format="[%(asctime)s %(levelname)s]\t%(message)s"
        )
    else:
        logging.basicConfig(
            level=logging.INFO, format="[%(asctime)s %(levelname)s]\t%(message)s"
        )
        
    if args.tracefile and args.interface:
        logging.error("No se debe usar --file y --itf a la vez")
        parser.print_help()
        sys.exit(-1)

    if args.tracefile is False and args.interface is False:
        logging.error("No se ha especificado interfaz ni fichero")
        parser.print_help()
        sys.exit(-1)

    signal.signal(signal.SIGINT, signal_handler)

    errbuf = bytearray()
    handle = None
    num_paquete = 0
    primer_timestamp = None
    ultimo_timestamp = None
    pdumper_NOIP = None
    pdumper_IP = None
    descr = None

    # TODO abrir la interfaz especificada para captura o la traza
    
    # TODO abrir un dumper para volcar el tráfico (si se ha especificado interfaz)
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

        descr = pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX)

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
    # TODO si se ha creado un dumper cerrarlo
    # Cerrar dumpers
    if pdumper_NOIP is not None:
        pcap_dump_close(pdumper_NOIP)

    if pdumper_IP is not None:
        pcap_dump_close(pdumper_IP)

    # Cerrar handle
    if handle is not None:
        pcap_close(handle)

    # Cerrar handle
    if descr is not None:
        pcap_close(descr)
