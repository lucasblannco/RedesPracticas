'''
    icmp.py
    
    Funciones necesarias para implementar el nivel ICMP
    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''
from ip import *
from threading import Lock
import struct

ICMP_PROTO = 1


ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REPLY_TYPE = 0

timeLock = Lock()
icmp_send_times = {}

def process_ICMP_message(us,header,data,srcIp):
    '''
        Nombre: process_ICMP_message
        Descripción: Esta función procesa un mensaje ICMP. Esta función se ejecutará por cada datagrama IP que contenga
        un 1 en el campo protocolo de IP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Calcular el checksum de ICMP y comprobar si es correcto:
            -Extraer campos tipo y código de la cabecera ICMP
            -Loggear (con logging.debug) el valor de tipo y código
            -Si el tipo es ICMP_ECHO_REQUEST_TYPE:
                -Generar un mensaje de tipo ICMP_ECHO_REPLY como respuesta. Este mensaje debe contener
                los datos recibidos en el ECHO_REQUEST. Es decir, "rebotamos" los datos que nos llegan.
                -Enviar el mensaje usando la función sendICMPMessage
            -Si el tipo es ICMP_ECHO_REPLY_TYPE:
                -Extraer del diccionario icmp_send_times el valor de tiempo de envío usando como clave los campos srcIP e icmp_id e icmp_seqnum
                contenidos en el mensaje ICMP. Restar el tiempo de envio extraído con el tiempo de recepción (contenido en la estructura pcap_pkthdr)
                -Se debe proteger el acceso al diccionario de tiempos usando la variable timeLock
                -Mostrar por pantalla la resta. Este valor será una estimación del RTT
            -Si es otro tipo:
                -No hacer nada

        Argumentos:
            -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
            -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
            -data: array de bytes con el conenido del mensaje ICMP
            -srcIP: dirección IP que ha enviado el datagrama actual.
        Retorno: Ninguno
          
    '''

    global icmp_send_times

    # Comprobamos que los datos recibidos contienen al menos la cabecera ICMP
    if len(data) < 8: return

    # Calculamos el checksum ICMP sobre el mensaje completo (cabecera + datos). Si la longitud es impar añadimos un byte a 0 para hacer el cálculo
    if len(data) % 2 == 1:
        datosChecksum = data + bytes(1)
    else:
        datosChecksum = data

    # Si el checksum no es correcto descartamos el mensaje
    if chksum(datosChecksum) != 0:
        logging.debug("Checksum ICMP incorrecto")
        return

    # Extraemos los campos tipo y código de la cabecera ICMP
    tipo = data[0]
    codigo = data[1]

    # Loggeamos el tipo y el código
    logging.debug(f"ICMP: type={tipo} code={codigo}")

    if tipo == ICMP_ECHO_REQUEST_TYPE:
        # Extraemos el identificador y el número de secuencia del mensaje recibido
        icmp_id = int.from_bytes(data[4:6], "big")
        icmp_seqnum = int.from_bytes(data[6:8], "big")

        # Rebotar los datos: mismo id y seqnum, tipo REPLY, con los mismos identificador, número de secuencia y datos del Request
        datos = data[8:]
        sendICMPMessage(datos, ICMP_ECHO_REPLY_TYPE, 0, icmp_id, icmp_seqnum, srcIp)

    elif tipo == ICMP_ECHO_REPLY_TYPE:
        # Extraemos el identificador y el número de secuencia del mensaje
        icmp_id = int.from_bytes(data[4:6], "big")
        icmp_seqnum = int.from_bytes(data[6:8], "big")

        # Tiempo de recepción del mensaje (contenido en la cabecera pcap)
        tiempoRecepcion = header.ts.tv_sec + header.ts.tv_usec / 1000000

        # Buscamos el tiempo de envío guardado para esta petición y lo eliminamos
        clave = (srcIp, icmp_id, icmp_seqnum)
        with timeLock:
            tiempoEnvio = icmp_send_times.pop(clave, None)

        # Si encontramos el tiempo de envío mostramos la estimación del RTT
        if tiempoEnvio is not None:
            rtt = tiempoRecepcion - tiempoEnvio
            print("RTT estimado: {:.6f} s".format(rtt))

    else:
        #Tipo no soportado: no hacemos nada
        return


    

def sendICMPMessage(data,type,code,icmp_id,icmp_seqnum,dstIP):
    '''
        Nombre: sendICMPMessage
        Descripción: Esta función construye un mensaje ICMP y lo envía.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Si el campo type es ICMP_ECHO_REQUEST_TYPE o ICMP_ECHO_REPLY_TYPE:
                -Construir la cabecera ICMP
                -Añadir los datos al mensaje ICMP
                -Calcular el checksum y añadirlo al mensaje donde corresponda
                -Si type es ICMP_ECHO_REQUEST_TYPE
                    -Guardar el tiempo de envío (llamando a time.time()) en el diccionario icmp_send_times
                    usando como clave el valor de dstIp+icmp_id+icmp_seqnum
                    -Se debe proteger al acceso al diccionario usando la variable timeLock

                -Llamar a sendIPDatagram para enviar el mensaje ICMP
                
            -Si no:
                -Tipo no soportado. Se devuelve False

        Argumentos:
            -data: array de bytes con los datos a incluir como payload en el mensaje ICMP
            -type: valor del campo tipo de ICMP
            -code: valor del campo code de ICMP 
            -icmp_id: entero que contiene el valor del campo ID de ICMP a enviar
            -icmp_seqnum: entero que contiene el valor del campo Seqnum de ICMP a enviar
            -dstIP: entero de 32 bits con la IP destino del mensaje ICMP
        Retorno: True o False en función de si se ha enviado el mensaje correctamente o no
          
    '''

    global icmp_send_times

    # Solo soportamos mensajes de tipo Echo Request y Echo Reply
    if type != ICMP_ECHO_REQUEST_TYPE and type != ICMP_ECHO_REPLY_TYPE:
        return False

    # Construimos la cabecera ICMP con el checksum a 0 de momento
    icmp_message = bytes([type, code])
    icmp_message += bytes(2)
    icmp_message += icmp_id.to_bytes(2, "big")
    icmp_message += icmp_seqnum.to_bytes(2, "big")

    # Añadimos los datos
    icmp_message += data

    # Calculamos el checksum sobre el mensaje completo (cabecera + datos). Si la longitud es impar añadimos un byte a 0 para el cálculo
    if len(icmp_message) % 2 == 1:
        datosChecksum = icmp_message + bytes(1)
    else:
        datosChecksum = icmp_message
    checksum = chksum(datosChecksum)

    # Añadimos el checksum en su campo correspondiente. El valor devuelto por checksum está en orden de red
    icmp_message = icmp_message[:2] + checksum.to_bytes(2, "big") + icmp_message[4:]

    # Si es un Echo Request guardamos el tiempo de envío para calcular el RTT
    if type == ICMP_ECHO_REQUEST_TYPE:
        clave = (dstIP, icmp_id, icmp_seqnum)
        with timeLock:
            icmp_send_times[clave] = time.time()

    # Enviamos el mensaje usando el nivel IP (protocolo 1)
    return sendIPDatagram(dstIP, icmp_message, ICMP_PROTO)
   
def initICMP():
    '''
        Nombre: initICMP
        Descripción: Esta función inicializa el nivel ICMP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar (llamando a registerIPProtocol) la función process_ICMP_message con el valor de protocolo 1

        Argumentos:
            -Ninguno
        Retorno: Ninguno
          
    '''
    # Registramos el nivel ICMP en la tabla de protocolos de nivel superior de IP
    registerIPProtocol(process_ICMP_message, ICMP_PROTO)