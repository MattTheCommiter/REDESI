'''
    ip.py
    
    Funciones necesarias para implementar el nivel IP
    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''
from socket import ETHERTYPE_IP

from ethernet import *
from arp import *
from fcntl import ioctl
import subprocess
SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b
NUMERO_DE_PAREJA = 11
IPID = 0
#Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
#por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols={}
#Tamaño mínimo de la cabecera IP
IP_MIN_HLEN = 20
#Tamaño máximo de la cabecera IP
IP_MAX_HLEN = 60
def chksum(msg):
    '''
        Nombre: chksum
        Descripción: Esta función calcula el checksum IP sobre unos datos de entrada dados (msg)
        Argumentos:
            -msg: array de bytes con el contenido sobre el que se calculará el checksum
        Retorno: Entero de 16 bits con el resultado del checksum en ORDEN DE RED
    '''
    s = 0
    y = 0xa29f    
    for i in range(0, len(msg), 2):
        if (i+1) < len(msg):
            a = msg[i] 
            b = msg[i+1]
            s = s + (a+(b << 8))
        elif (i+1)==len(msg):
            s += msg[i]
        else:
            raise 'Error calculando el checksum'
    y = y & 0x00ff
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def getMTU(interface):
    '''
        Nombre: getMTU
        Descripción: Esta función obteiene la MTU para un interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la MTU
        Retorno: Entero con el valor de la MTU para la interfaz especificada
    '''
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    ifr = struct.pack('16sH', interface.encode("utf-8"), 0)
    mtu = struct.unpack('16sH', ioctl(s,SIOCGIFMTU, ifr))[1]
   
    s.close()
   
    return mtu
   
def getNetmask(interface):
    '''
        Nombre: getNetmask
        Descripción: Esta función obteiene la máscara de red asignada a una interfaz 
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la máscara
        Retorno: Entero de 32 bits con el valor de la máscara de red
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
       SIOCGIFNETMASK,
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]


def getDefaultGW(interface):
    '''
        Nombre: getDefaultGW
        Descripción: Esta función obteiene el gateway por defecto para una interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar el gateway
        Retorno: Entero de 32 bits con la IP del gateway
    '''
    p = subprocess.Popen(['ip r | grep default | awk \'{print $3}\''], stdout=subprocess.PIPE, shell=True)
    dfw = p.stdout.read().decode('utf-8')
    print(dfw)
    return struct.unpack('!I',socket.inet_aton(dfw))[0]



def process_IP_datagram(us:ctypes.c_void_p,header:pcap_pkthdr,data:bytes,srcMac:bytes):
    '''
        Nombre: process_IP_datagram
        Descripción: Esta función procesa datagramas IP recibidos.
            Se ejecuta una vez por cada trama Ethernet recibida con Ethertype 0x0800
            Esta función debe realizar, al menos, las siguientes tareas:
                -Extraer los campos de la cabecera IP (includa la longitud de la cabecera)
                -Calcular el checksum y comprobar que es correcto                    
                -Analizar los bits de de MF y el offset. Si el offset tiene un valor != 0 dejar de procesar el datagrama (no vamos a reensamblar)
                -Loggear (usando logging.debug) el valor de los siguientes campos:
                    -Longitud de la cabecera IP
                    -IPID
                    -TTL
                    -Valor de las banderas DF y MF
                    -Valor de offset
                    -IP origen y destino
                    -Protocolo
                -Comprobar si tenemos registrada una función de callback de nivel superior consultando el diccionario protocols y usando como
                clave el valor del campo protocolo del datagrama IP.
                    -En caso de que haya una función de nivel superior registrada, debe llamarse a dicha funciñón 
                    pasando los datos (payload) contenidos en el datagrama IP.
        
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido del datagrama IP
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''
    global protocols

    unpackedData = struct.unpack('!BBHHHBB', data[:10])
    version_and_ihl = unpackedData[0]
    serviceType = unpackedData[1]
    totalLength = unpackedData[2]
    ipid = unpackedData[3]
    flags_and_offset = unpackedData[4]
    ttl = unpackedData[5]
    protocol = unpackedData[6]
    # Extraemos el checksum respetando el orden de red
    headerChecksum = struct.unpack('H', data[10:12])[0]
    # Usamos el orden deseado para el resto de la cabecera
    unpackedData = struct.unpack('!II', data[12:20])
    srcIP = unpackedData[0]
    destIP = unpackedData[1]
    
    ihl = version_and_ihl & 0xF
    if ihl < 5:
        return
    unpackedData =struct.unpack(f'!{ihl*4 - 20}s', data[20:(ihl*4)])
    options = unpackedData[0]

    if chksum(data[:ihl*4]) != 0x00:
        return
    
    df_bit = (flags_and_offset & (1 << 14)) >> 14
    mf_bit = (flags_and_offset & (1 << 13)) >> 13
    offset = flags_and_offset & 0x1FFF
    if offset != 0x00:
        return
    logging.debug(f"Longitud de la cabecera IP: {ihl}")
    logging.debug(f"IPID: {ipid}")
    logging.debug(f"TTL: {ttl}")
    logging.debug(f"Valor de flag DF: {df_bit}")
    logging.debug(f"Valor de flag MF: {mf_bit}")
    logging.debug(f"Valor del offset: {offset}")
    logging.debug(f"IP origen: {socket.inet_ntoa(struct.pack('!I', srcIP))}")
    logging.debug(f"IP destino: {socket.inet_ntoa(struct.pack('!I', destIP))}")
    logging.debug(f"Protocolo: {protocol}")

    if protocol in protocols:
        src_ip_str = socket.inet_ntoa(struct.pack('!I', srcIP))
        protocols.get(protocol)(us, header, data[(ihl*4):totalLength], src_ip_str)




def registerIPProtocol(callback,protocol):
    '''
        Nombre: registerIPProtocol
        Descripción: Esta función recibirá el nombre de una función y su valor de protocolo IP asociado y añadirá en la tabla 
            (diccionario) de protocolos de nivel superior dicha asociación. 
            Este mecanismo nos permite saber a qué función de nivel superior debemos llamar al recibir un datagrama IP  con un 
            determinado valor del campo protocolo (por ejemplo TCP o UDP).
            Por ejemplo, podemos registrar una función llamada process_UDP_datagram asociada al valor de protocolo 17 y otra 
            llamada process_ICMP_message asocaida al valor de protocolo 1. 
        Argumentos:
            -callback_fun: función de callback a ejecutar cuando se reciba el protocolo especificado. 
                La función que se pase como argumento debe tener el siguiente prototipo: funcion(us,header,data,srcIp):
                Dónde:
                    -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
                    -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
                    -data: payload del datagrama IP. Es decir, la cabecera IP NUNCA se pasa hacia arriba.
                    -srcIP: dirección IP que ha enviado el datagrama actual.
                La función no retornará nada. Si un datagrama se quiere descartar basta con hacer un return sin valor y dejará de procesarse.
            -protocol: valor del campo protocolo de IP para el cuál se quiere registrar una función de callback.
        Retorno: Ninguno 
    '''
    protocols[protocol] = callback

def initIP(interface,opts=None):
    global myIP, MTU, netmask, defaultGW,ipOpts, IPID
    '''
        Nombre: initIP
        Descripción: Esta función inicializará el nivel IP. Esta función debe realizar, al menos, las siguientes tareas:
            -Llamar a initARP para inicializar el nivel ARP
            -Obtener (llamando a las funciones correspondientes) y almacenar en variables globales los siguientes datos:
                -IP propia
                -MTU
                -Máscara de red (netmask)
                -Gateway por defecto
            -Almacenar el valor de opts en la variable global ipOpts
            -Registrar a nivel Ethernet (llamando a registerCallback) la función process_IP_datagram con el Ethertype 0x0800
            -Inicializar el valor de IPID con el número de pareja
        Argumentos:
            -interface: cadena de texto con el nombre de la interfaz sobre la que inicializar ip
            -opts: array de bytes con las opciones a nivel IP a incluir en los datagramas o None si no hay opciones a añadir
        Retorno: True o False en función de si se ha inicializado el nivel o no
    '''
    initARP(interface)
    myIP = getIP(interface)
    netmask = getNetmask(interface)
    MTU = getMTU(interface)
    defaultGW = getDefaultGW(interface)
    IPID = NUMERO_DE_PAREJA

    ipOpts = opts

    registerEthCallback(process_IP_datagram, 0x800)

    return True


# ---------------------------------------------------------------------------
# Funciones auxiliares para processIPDatagram
# ---------------------------------------------------------------------------

def _build_ip_header(version_and_ihl, service_type, total_length, ipid, flags_and_offset, ttl, protocol, checksum, srcIP, destIP, ipOpts):
    '''
        Construye la cabecera IP completa mediante struct.pack (incluyendo las opciones si las hubiera)
    '''
    header = struct.pack('!BBHHHBB',version_and_ihl, service_type, total_length, ipid, flags_and_offset, ttl, protocol)
    # Respetamos el orden de red en el checksum
    header += struct.pack('H',checksum)
    header += struct.pack('!II', srcIP, destIP)
    if ipOpts:
        header += ipOpts
    return header


def _resolve_dst_mac(dstIP, myIP, netmask, defaultGW):
    '''
        Determina el próximo salto según la máscara de red y resuelve su MAC mediante ARP.
        Retorna la dirección MAC (bytes) o None si no se pudo resolver.
    '''
    if (dstIP & netmask) == (myIP & netmask):
        next_hop = dstIP          # entrega local
    else:
        next_hop = defaultGW      # enviar al router

    dstMac = ARPResolution(next_hop)
    return dstMac   # puede ser None si ARP falla


def sendIPDatagram(dstIP,data,protocol):
    global IPID
    '''
        Nombre: sendIPDatagram
        Descripción: Esta función construye un datagrama IP y lo envía. En caso de que los datos a enviar sean muy grandes la función
        debe generar y enviar el número de fragmentos IP que sean necesarios.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Determinar si se debe fragmentar o no y calcular el número de fragmentos
            -Para cada datagrama o fragmento:
                -Construir la cabecera IP con los valores que corresponda.Incluir opciones en caso de que ipOpts sea distinto de None
                -Calcular el checksum sobre la cabecera y añadirlo a la cabecera
                -Añadir los datos a la cabecera IP
                -En el caso de que sea un fragmento ajustar los valores de los campos MF y offset de manera adecuada
                -Enviar el datagrama o fragmento llamando a sendEthernetFrame. Para determinar la dirección MAC de destino
                al enviar los datagramas se debe hacer unso de la máscara de red:                  
            -Para cada datagrama (no fragmento):
                -Incrementar la variable IPID en 1.
        Argumentos:
            -dstIP: entero de 32 bits con la IP destino del datagrama 
            -data: array de bytes con los datos a incluir como payload en el datagrama
            -protocol: valor numérico del campo IP protocolo que indica el protocolo de nivel superior de los datos
            contenidos en el payload. Por ejemplo 1, 6 o 17.
        Retorno: True o False en función de si se ha enviado el datagrama correctamente o no
          
    '''
    header_len = 20 + len(ipOpts or b'')
    ihl = header_len // 4
    version_and_ihl = 0x40 + ihl
    serviceType = 1
    ttl = 40
    srcIP = myIP
    destIP = dstIP
    ipid = IPID

    # Tamaño máximo de datos útiles por fragmento (debe ser múltiplo de 8)
    usable_MTU = MTU - header_len
    max_data = (usable_MTU // 8) * 8

    if max_data <= 0:
        # La MTU es demasiado pequeña para transportar siquiera la cabecera IP
        return False

    offset = 0
    while offset < len(data):
        frag = data[offset: offset + max_data]
        is_last = (offset + len(frag)) == len(data)

        # MF = 0 en el último fragmento, 1 en los demás
        mf = 0 if is_last else 1

        frag_offset = offset // 8   # el offset se calcula en palabras de 8 bytes
        flags_and_offset = (0 << 14) + (mf << 13) + frag_offset   # DF = 0

        total_len = header_len + len(frag)

        # Cabecera con checksum a cero para calcularlo
        ip_header = _build_ip_header(version_and_ihl, serviceType, total_len, ipid,
                                     flags_and_offset, ttl, protocol, 0,
                                     srcIP, destIP, ipOpts)
        headerChecksum = chksum(ip_header)

        # Cabecera final con el checksum real
        ip_header = _build_ip_header(version_and_ihl, serviceType, total_len, ipid,
                                     flags_and_offset, ttl, protocol,
                                     headerChecksum, srcIP, destIP, ipOpts)

        frame = ip_header + frag

        dstMac = _resolve_dst_mac(dstIP, myIP, netmask, defaultGW)
        if dstMac is None:
            return False

        sendEthernetFrame(frame, len(frame), 0x800, dstMac)
        offset += len(frag)

    IPID += 1
    return True
