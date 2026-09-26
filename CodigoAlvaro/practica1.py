'''
    practica1.py
    Muestra el tiempo de llegada de los primeros 50 paquetes a la interfaz especificada
    como argumento y los vuelca a traza nueva con tiempo actual

    Autor: Javier Ramos <javier.ramos@uam.es>
    2020 EPS-UAM
'''

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
num_paquete = 0
TIME_OFFSET = 30*60

def signal_handler(nsignal,frame):
	logging.info('Control C pulsado')
	if handle:
		pcap_breakloop(handle)
		

def procesa_paquete(us,header,data):
	global num_paquete, pdumper_especial, pdumper_todos, primer_timestamp, ultimo_timestamp, nbytes

	logging.info('Nuevo paquete de {} bytes capturado en el timestamp UNIX {}.{}'.format(header.len,header.ts.tv_sec,header.ts.tv_usec))
	num_paquete += 1

	#Captura del tiempo para calcular al final del programa
	if primer_timestamp is None:
		primer_timestamp = header.ts.tv_sec

	ultimo_timestamp = header.ts.tv_sec

	#Volcamos todos los paquetes en una traza, los que cumplen la condicion de bytes 12 y 13 en otro, si se especifico la interfaz y existen los dump
	if pdumper_especial is not None and pdumper_todos is not None:
		if data[12] == 0x08 and data[13] == 0x06:
			pcap_dump(pdumper_especial, header, data)
		else:
			pcap_dump(pdumper_todos, header, data)

	#TODO imprimir los N primeros bytes

	#imprimimos byte a byte y moviendonos por lineas de 16 bytes, si nbytes default se imprime todo
	if nbytes is None:
		cabecera = data
	else:
		cabecera = data[:nbytes]

	for i in range(0, len(cabecera), 16):
		linea = cabecera[i : i + 16]
		hexadecimal = ' '.join(format(byte, '02X') for byte in linea)
		logging.info(hexadecimal)
		

	#Escribir el tráfico al fichero de captura con el offset temporal

	
if __name__ == "__main__":
	global pdumper,args,handle
	parser = argparse.ArgumentParser(description='Captura tráfico de una interfaz ( o lee de fichero) y muestra la longitud y timestamp de los 50 primeros paquetes',
	formatter_class=RawTextHelpFormatter)
	parser.add_argument('--file', dest='tracefile', default=False,help='Fichero pcap a abrir')
	parser.add_argument('--itf', dest='interface', default=False,help='Interfaz a abrir')
	parser.add_argument('--nbytes', dest='nbytes', type=int, default=None,help='Número de bytes a mostrar por paquete') #Cambio el default porque dicen que se imprima todo si no me lo dan
	parser.add_argument('--debug', dest='debug', default=False, action='store_true',help='Activar Debug messages')
	parser.add_argument('--npkts', dest='npkts', default=-1, type=int, help='El numero de paquetes que se quieren procesar')
	args = parser.parse_args()

	if args.debug:
		logging.basicConfig(level = logging.DEBUG, format = '[%(asctime)s %(levelname)s]\t%(message)s')
	else:
		logging.basicConfig(level = logging.INFO, format = '[%(asctime)s %(levelname)s]\t%(message)s')

	if args.tracefile is False and args.interface is False:
		logging.error('No se ha especificado interfaz ni fichero')
		parser.print_help()
		sys.exit(-1)

	signal.signal(signal.SIGINT, signal_handler)

	errbuf = bytearray()
	handle = None
	pdumper_todos = None
	pdumper_especial = None
	primer_timestamp = None
	ultimo_timestamp = None
	nbytes = args.nbytes
	
	#TODO abrir la interfaz especificada para captura o la traza
	if args.tracefile:
		handle = pcap_open_offline(args.tracefile,errbuf)
	elif args.interface:
		handle = pcap_open_live(args.interface,ETH_FRAME_MAX,NO_PROMISC,TO_MS, errbuf)

	if handle is None:
			logging.error(errbuf)
			sys.exit(-1)


	
	#TODO abrir un dumper para volcar el tráfico (si se ha especificado interfaz) 
	if args.interface:
		descr = pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX)
		fecha = int(time.time())
		pdumper_especial = pcap_dump_open(descr,"capturaNOIP.{}.{}.pcap".format(args.interface, fecha))
		pdumper_todos = pcap_dump_open(descr,"captura.{}.{}.pcap".format(args.interface, fecha))
	
	
	ret = pcap_loop(handle,args.npkts,procesa_paquete,None)
	if ret == -1:
		logging.error('Error al capturar un paquete')
	elif ret == -2:
		logging.debug('pcap_breakloop() llamado')
	elif ret == 0:
		logging.debug('No mas paquetes o limite superado')

	#Imprimimos los dato que piden en el apartado 2
	logging.info('{} paquetes procesados'.format(num_paquete))

	if ultimo_timestamp is None:
		dif = 0
	else:
		dif = ultimo_timestamp - primer_timestamp
	logging.info('Diferencia en segundos entre primer y ultimo paquete : {}'.format(dif))
	#TODO si se ha creado un dumper cerrarlo
	pcap_close(handle)
	
	if args.interface:
		pcap_close(descr)
		pcap_dump_close(pdumper_especial)
		pcap_dump_close(pdumper_todos)

	

