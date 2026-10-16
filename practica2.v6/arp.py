"""
arp.py
Implementación del protocolo ARP y funciones auxiliares que permiten realizar resoluciones de direcciones IP.
Autor: Javier Ramos <javier.ramos@uam.es>
2019 EPS-UAM
"""

from ethernet import *
import logging
import socket
import struct
import fcntl
import time
from threading import Lock
from expiringdict import ExpiringDict

# Semáforo global
globalLock = Lock()
# Dirección de difusión (Broadcast)
broadcastAddr = bytes([0xFF] * 6)
# Cabecera ARP común a peticiones y respuestas. Específica para la combinación Ethernet/IP
ARPHeader = bytes([0x00, 0x01, 0x08, 0x00, 0x06, 0x04])
# longitud (en bytes) de la cabecera común ARP
ARP_HLEN = 6

# Variable que alamacenará que dirección IP se está intentando resolver
requestedIP = None
# Variable que alamacenará que dirección MAC resuelta o None si no se ha podido obtener
resolvedMAC = None
# Variable que alamacenará True mientras estemos esperando una respuesta ARP
awaitingResponse = False

# Datos de nuestra interfaz
myIP = None
myMAC = None
arpInitialized = False

# Evitamos varias resoluciones ARP al mismo tiempo
resolutionLock = Lock()

# Variable para proteger la caché
cacheLock = Lock()
# Caché de ARP. Es un diccionario similar al estándar de Python solo que eliminará las entradas a los 10 segundos
cache = ExpiringDict(max_len=100, max_age_seconds=10)


def getIP(interface: str) -> int:
    """
    Nombre: getIP
    Descripción: Esta función obtiene la dirección IP asociada a una interfaz. Esta funció NO debe ser modificada
    Argumentos:
        -interface: nombre de la interfaz
    Retorno: Entero de 32 bits con la dirección IP de la interfaz
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack("256s", (interface[:15].encode("utf-8"))),
    )[20:24]
    s.close()
    return struct.unpack("!I", ip)[0]


def printCache() -> None:
    """
    Nombre: printCache
    Descripción: Esta función imprime la caché ARP
    Argumentos: Ninguno
    Retorno: Ninguno
    """
    print("{:>12}\t\t{:>12}".format("IP", "MAC"))
    with cacheLock:
        for k in cache:
            if k in cache:
                print(
                    "{:>12}\t\t{:>12}".format(
                        socket.inet_ntoa(struct.pack("!I", k)),
                        ":".join(["{:02X}".format(b) for b in cache[k]]),
                    )
                )


def processARPRequest(data: bytes, MAC: bytes) -> None:
    """
    Nombre: processARPRequest
    Decripción: Esta función procesa una petición ARP. Esta función debe realizar, al menos, las siguientes tareas:
        -Extraer la MAC origen contenida en la petición ARP
        -Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
        -Extraer la IP origen contenida en la petición ARP
        -Extraer la IP destino contenida en la petición ARP
        -Comprobar si la IP destino de la petición ARP es la propia IP:
            -Si no es la propia IP retornar
            -Si es la propia IP:
                -Construir una respuesta ARP llamando a createARPReply (descripción más adelante)
                -Enviar la respuesta ARP usando el nivel Ethernet (sendEthernetFrame)
    Argumentos:
        -data: bytearray con el contenido de la trama ARP (después de la cabecera común)
        -MAC: dirección MAC origen extraída por el nivel Ethernet
    Retorno: Ninguno
    """
# Comprobamos que tenemos todos los campos ARP
    if len(data) < 22:
        return

    # Obtenemos la MAC del ordenador que pregunta
    macOrigen = data[2:8]

    # Comprobamos que coincide con la MAC de Ethernet
    if macOrigen != MAC:
        return
    
    # No respondemos a nuestras propias peticiones
    if macOrigen == myMAC:
        return

    # Obtenemos la IP del ordenador que pregunta
    ipOrigen = int.from_bytes(data[8:12], "big")

    # Obtenemos la IP por la que están preguntando
    ipDestino = int.from_bytes(data[18:22], "big")

    # Si no preguntan por nuestra IP, no respondemos
    if ipDestino != myIP:
        return

    # Construimos la respuesta ARP
    respuesta = createARPReply(ipOrigen, macOrigen)

    # Enviamos la respuesta al ordenador que nos ha preguntado
    sendEthernetFrame(respuesta, len(respuesta), 0x0806, macOrigen)


def processARPReply(data: bytes, MAC: bytes) -> None:
    """
    Nombre: processARPReply
    Decripción: Esta función procesa una respuesta ARP. Esta función debe realizar, al menos, las siguientes tareas:
        -Extraer la MAC origen contenida en la petición ARP
        -Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
        -Extraer la IP origen contenida en la petición ARP
        -Extraer la MAC destino contenida en la petición ARP
        -Extraer la IP destino contenida en la petición ARP
        -Comprobar si la IP destino de la petición ARP es la propia IP:
            -Si no es la propia IP retornar
            -Si es la propia IP:
                -Comprobar si la IP origen se corresponde con la solicitada (requestedIP). Si no se corresponde retornar
                -Copiar la MAC origen a la variable global resolvedMAC
                -Añadir a la caché ARP la asociación MAC/IP.
                -Cambiar el valor de la variable awaitingResponse a False
                -Cambiar el valor de la variable requestedIP a None
    Las variables globales (requestedIP, awaitingResponse y resolvedMAC) son accedidas concurrentemente por la función ARPResolution y deben ser protegidas mediante un Lock.
    Argumentos:
        -data: bytearray con el contenido de la trama ARP (después de la cabecera común)
        -MAC: dirección MAC origen extraída por el nivel Ethernet
    Retorno: Ninguno
    """
    global requestedIP, resolvedMAC, awaitingResponse, cache

    # Comprobamos que están todos los campos ARP
    if len(data) < 22:
        return

    # Sacamos la MAC del ordenador que responde
    macOrigen = data[2:8]

    # Comprobamos que coincide con la MAC de Ethernet
    if macOrigen != MAC:
        return
    
    # No respondemos a nuestras propias peticiones
    if macOrigen == myMAC:
        return

    # Sacamos la IP del ordenador que responde
    ipOrigen = int.from_bytes(data[8:12], "big")

    # Sacamos la MAC y la IP de destino
    macDestino = data[12:18]
    ipDestino = int.from_bytes(data[18:22], "big")

    # Comprobamos que la respuesta es para nosotros
    if ipDestino != myIP or macDestino != myMAC:
        return

    # Protegemos las variables compartidas con un Lock
    with globalLock:

        # Comprobamos que estamos esperando esta respuesta
        if not awaitingResponse or requestedIP != ipOrigen:
            return

        # Guardamos la IP y MAC en la caché ARP
        with cacheLock:
            cache[ipOrigen] = macOrigen

        # Guardamos la MAC que hemos encontrado
        resolvedMAC = macOrigen

        # Indicamos que ya tenemos la respuesta
        awaitingResponse = False
        requestedIP = None


def createARPRequest(ip: int) -> bytes:
    """
    Nombre: createARPRequest
    Descripción: Esta función construye una petición ARP y devuelve la trama con el contenido.
    Argumentos:
        -ip: dirección a resolver
    Retorno: Bytes con el contenido de la trama de petición ARP
    """
    global myMAC, myIP
    frame = bytes()
    # Cabecera común del protocolo ARP
    frame = ARPHeader

    # Operación ARP Request (1)
    frame = frame + (1).to_bytes(2, "big")

    # Nuestra dirección MAC
    frame = frame + myMAC

    # Nuestra dirección IP
    frame = frame + myIP.to_bytes(4, "big")

    # MAC destino desconocida: seis bytes a cero
    frame = frame + bytes(6)

    # Dirección IP que queremos resolver
    frame = frame + ip.to_bytes(4, "big")

    return frame



def createARPReply(IP: int, MAC: bytes) -> bytes:
    """
    Nombre: createARPReply
    Descripción: Esta función construye una respuesta ARP y devuelve la trama con el contenido.
    Argumentos:
        -IP: dirección IP a la que contestar
        -MAC: dirección MAC a la que contestar
    Retorno: Bytes con el contenido de la trama de petición ARP
    """
    global myMAC, myIP
    frame = bytes()
    
     # Añadimos la cabecera común de ARP
    frame = ARPHeader

    # Indicamos que es una respuesta ARP (opcode 2)
    frame = frame + (2).to_bytes(2, "big")

    # Añadimos nuestra MAC
    frame = frame + myMAC

    # Añadimos nuestra IP
    frame = frame + myIP.to_bytes(4, "big")

    # Añadimos la MAC del equipo que nos ha preguntado
    frame = frame + MAC

    # Añadimos la IP del equipo que nos ha preguntado
    frame = frame + IP.to_bytes(4, "big")

    return frame



def process_arp_frame(
    us: ctypes.c_void_p, header: pcap_pkthdr, data: bytes, srcMac: bytes
) -> None:
    """
    Nombre: process_arp_frame
    Descripción: Esta función procesa las tramas ARP.
        Se ejecutará por cada trama Ethenet que se reciba con Ethertype 0x0806 (si ha sido registrada en initARP).
        Esta función debe realizar, al menos, las siguientes tareas:
            -Extraer la cabecera común de ARP (6 primeros bytes) y comprobar que es correcta
            -Extraer el campo opcode
            -Si opcode es 0x0001 (Request) llamar a processARPRequest (ver descripción más adelante)
            -Si opcode es 0x0002 (Reply) llamar a processARPReply (ver descripción más adelante)
            -Si es otro opcode retornar de la función
            -En caso de que no exista retornar
    Argumentos:
        -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
        -header: cabecera pcap_pktheader
        -data: array de bytes con el contenido de la trama ARP
        -srcMac: MAC origen de la trama Ethernet que se ha recibido
    Retorno: Ninguno
    """

    # Comprobamos que el paquete ARP tiene al menos 28 bytes
    if len(data) < 28:
        return

    # Extraemos los 6 primeros bytes de la cabecera ARP
    cabecera = data[0:6]

    # Comprobamos que la cabecera es correcta
    if cabecera != ARPHeader:
        return

    # Obtenemos el opcode para saber si es Request o Reply
    opcode = int.from_bytes(data[6:8], "big")

    # Quitamos los 6 bytes de la cabecera común
    datosARP = data[6:]

    # Si es una petición ARP
    if opcode == 1:
        processARPRequest(datosARP, srcMac)

    # Si es una respuesta ARP
    elif opcode == 2:
        processARPReply(datosARP, srcMac)

    # Si es otra operación, descartamos el paquete
    else:
        return


def initARP(interface: str) -> int:
    """
    Nombre: initARP
    Descripción: Esta función construirá inicializará el nivel ARP. Esta función debe realizar, al menos, las siguientes tareas:
        -Registrar la función del callback process_arp_frame con el Ethertype 0x0806
        -Obtener y almacenar la dirección MAC e IP asociadas a la interfaz especificada
        -Realizar una petición ARP gratuita y comprobar si la IP propia ya está asignada. En caso positivo se debe devolver error.
        -Marcar la variable de nivel ARP inicializado a True
    """
    global myIP, myMAC, arpInitialized
    # Comprobamos si ARP ya estaba inicializado
    if arpInitialized:
        return -1

    try:
        myIP = getIP(interface)
        myMAC = getHwAddr(interface)

    except Exception as e:
        logging.error("Error al obtener IP o MAC: %s", e)
        return -1

    # Registramos el protocolo ARP en Ethernet
    registerEthCallback(process_arp_frame, 0x0806)

    # Comprobamos si otro equipo utiliza nuestra IP
    macEncontrada = ARPResolution(myIP)

    # Si alguien tiene nuestra IP con otra MAC, hay conflicto
    if macEncontrada is not None and macEncontrada != myMAC:
        logging.error("La direccion IP esta repetida")
        return -1

    # Marcamos ARP como inicializado
    arpInitialized = True

    return 0



def ARPResolution(ip: int) -> bytes:
    """
    Nombre: ARPResolution
    Descripción: Esta función intenta realizar una resolución ARP para una IP dada y devuelve la dirección MAC asociada a dicha IP
        o None en caso de que no haya recibido respuesta. Esta función debe realizar, al menos, las siguientes tareas:
            -Comprobar si la IP solicitada existe en la caché:
            -Si está en caché devolver la información de la caché
            -Si no está en la caché:
                -Construir una petición ARP llamando a la función createARPRequest (descripción más adelante)
                -Enviar dicha petición
                -Comprobar si se ha recibido respuesta o no:
                    -Si no se ha recibido respuesta reenviar la petición hasta un máximo de 3 veces. Si no se recibe respuesta devolver None
                    -Si se ha recibido respuesta devolver la dirección MAC
        Esta función necesitará comunicarse con el la función de recepción (para comprobar si hay respuesta y la respuesta en sí) mediante 3 variables globales:
            -awaitingResponse: indica si está True que se espera respuesta. Si está a False quiere decir que se ha recibido respuesta
            -requestedIP: contiene la IP por la que se está preguntando
            -resolvedMAC: contiene la dirección MAC resuelta (en caso de que awaitingResponse) sea False.
        Como estas variables globales se leen y escriben concurrentemente deben ser protegidas con un Lock
    """
    global requestedIP, awaitingResponse, resolvedMAC
     # Evitamos hacer varias resoluciones al mismo tiempo
    with resolutionLock:

        # Miramos si la IP ya esta en la cache
        with cacheLock:
            mac = cache.get(ip)

        if mac is not None:
            return mac

        # Preparamos la peticion ARP
        peticion = createARPRequest(ip)

        with globalLock:
            requestedIP = ip
            awaitingResponse = True
            resolvedMAC = None

        # Enviamos la peticion y reintentamos hasta 3 veces
        for intento in range(4):

            with globalLock:
                if not awaitingResponse:
                    break

            if sendEthernetFrame(peticion, len(peticion), 0x0806, broadcastAddr) == -1:
                break

            # Esperamos como maximo un segundo
            inicio = time.monotonic()

            while time.monotonic() - inicio < 1:
                with globalLock:
                    if not awaitingResponse:
                        break

                time.sleep(0.05)

        # Guardamos el resultado y limpiamos las variables
        with globalLock:
            mac = resolvedMAC
            requestedIP = None
            resolvedMAC = None
            awaitingResponse = False

        return mac
