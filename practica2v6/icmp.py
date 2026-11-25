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


# ---------------------------------------------------------------------------
# Funciones auxiliares para processICMPmessage
# ---------------------------------------------------------------------------


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
    #alcular el checksum
    unpacked_data = struct.unpack('!BBHHH', data[:8])
    type = unpacked_data[0]
    code = unpacked_data[1]
    id = unpacked_data[3]
    seq_num = unpacked_data[4]
    datos = data[8 : ]

    checksum = chksum(data) #valor del checksum con cabecera y datos, todo para dentro

    #comprobamos que el valor de checksum es correcto
    if(checksum != 0x0):
        return

    logging.debug(f"Tipo de mensaje ICMP: {type}")
    logging.debug(f"Codigo subtipo ICMP: {code}")

    if type == ICMP_ECHO_REQUEST_TYPE:
        logging.debug(f"Mandando respuesta de ICMP")
        sendICMPMessage(datos, ICMP_ECHO_REPLY_TYPE, code, id, seq_num, srcIp) #mandamos el mensaje de vuelta, mismos datos

    elif type == ICMP_ECHO_REPLY_TYPE:
        with timeLock:
            send_time = icmp_send_times[srcIp + id + seq_num]

        received_time = header.ts.tv_sec + header.ts.tv_usec / 1000000
        rtt = received_time - send_time
        logging.info(f"El valor de RTT obtenido : {rtt:.6f} segundos")

    else: 
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
    if type == ICMP_ECHO_REPLY_TYPE or type == ICMP_ECHO_REQUEST_TYPE:
        icmp_message = bytes()
        new_header = struct.pack('!BBHHH',type, code, 0, icmp_id, icmp_seqnum)

        icmp_message = new_header + data

        checksum = chksum(icmp_message)

        new_header = struct.pack('!BB', type, code)
        new_header += struct.pack('H',checksum) #metemos el checksum en little endian
        new_header += struct.pack('!HH', icmp_id, icmp_seqnum)

        icmp_message = new_header + data

        if type == ICMP_ECHO_REQUEST_TYPE:
            with timeLock:
                icmp_send_times[dstIP + icmp_id + icmp_seqnum] = time.time()

        return sendIPDatagram(dstIP, icmp_message, ICMP_PROTO)

    return False
         

    
   
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
    registerIPProtocol(process_ICMP_message, ICMP_PROTO)