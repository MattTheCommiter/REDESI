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
from datetime import datetime

ETH_FRAME_MAX = 1514
PROMISC = 1
NO_PROMISC = 0
TO_MS = 10
num_paquete = 0
TIME_OFFSET = 30*60


def compute_time(first_time, last_time):
	usec = last_time.tv_usec - first_time.tv_usec
	sec = last_time.tv_sec - first_time.tv_sec
	if(usec < 0):
		usec += 1000
		sec -= 1
	return f"{sec}.{usec}"

#Handler para cuando llega una interrupción
def signal_handler(nsignal,frame):
	logging.info('Control C pulsado')
	if handle:
		#Se detiene el loop de lectura de paquetes
		pcap_breakloop(handle)
		

def procesa_paquete(us,header,data):
	global num_paquete, pdumper, pdumper2, first_time, last_time
	logging.info('Nuevo paquete de {} bytes capturado en el timestamp UNIX {}.{}'.format(header.len,header.ts.tv_sec,header.ts.tv_usec))

	#Guardamos el tiempo del primer paquete
	if num_paquete == 0:
		first_time = header.ts
	last_time = header.ts


	#imprimir los N primeros bytes
	if num_paquete < args.npkts or args.npkts == -1:
		formatted_data = binascii.hexlify(data).upper()

		byte_line_count = 0;
		bytes_total_count = 0;

		while bytes_total_count < args.nbytes or (args.nbytes == -1 and bytes_total_count < len(formatted_data)):
			sys.stdout.write(f"{formatted_data[bytes_total_count]} "),
			bytes_total_count+=1
			byte_line_count +=1
			if(byte_line_count == 16):
				sys.stdout.write("\n")
				byte_line_count = 0
			sys.stdout.flush()
		print("")

	if args.interface:
		#Escribimos en un fichero u otro en función de si se cumple la condición
		if data[12] == 0x08 and data[13] == 0x06:
			pcap_dump(pdumper, header, data)
		else:
			pcap_dump(pdumper2, header, data)


	num_paquete += 1

if __name__ == "__main__":
	global pdumper, args, handle, pdumper2


	parser = argparse.ArgumentParser(description='Captura tráfico de una interfaz ( o lee de fichero) y muestra la longitud y timestamp de los 50 primeros paquetes',
	formatter_class=RawTextHelpFormatter)
	parser.add_argument('--file', dest='tracefile', default=False,help='Fichero pcap a abrir')
	parser.add_argument('--itf', dest='interface', default=False,help='Interfaz a abrir')
	#parser.add_argument('--nbytes', dest='nbytes', type=int, default=14,help='Número de bytes a mostrar por paquete')
	parser.add_argument('--nbytes', dest='nbytes', type=int, default=-1,help='Número de bytes a mostrar por paquete')
	parser.add_argument('--npkts', dest='npkts', type=int, default=-1,help='Número de paquetes a procesar')
	parser.add_argument('--debug', dest='debug', default=False, action='store_true',help='Activar Debug messages')
	args = parser.parse_args()

	if args.debug:
		logging.basicConfig(level = logging.DEBUG, format = '[%(asctime)s %(levelname)s]\t%(message)s')
	else:
		logging.basicConfig(level = logging.INFO, format = '[%(asctime)s %(levelname)s]\t%(message)s')

	if args.tracefile is False and args.interface is False:
		logging.error('No se ha especificado interfaz ni fichero')
		parser.print_help()
		sys.exit(-1)



	#Definimos el handler para la señal de interrupción
	signal.signal(signal.SIGINT, signal_handler)

	#Inicializamos nuestras variables
	errbuf = bytearray()

	
	#TODO abrir la interfaz especificada para captura o la traza
	if args.interface:
		handle = pcap_open_live(args.interface, ETH_FRAME_MAX, PROMISC, TO_MS, errbuf)
		# TODO abrir un dumper para volcar el tráfico (si se ha especificado interfaz)
		pdumper = pcap_dump_open(handle, "capturaNOIP." + f"{args.interface}" + "." + f"{datetime.date(datetime.today())}" + ".pcap")
		pdumper2 = pcap_dump_open(handle, "captura." + f"{args.interface}" + "." + f"{datetime.date(datetime.today())}" + ".pcap")
	else:
		handle = pcap_open_offline(args.tracefile, errbuf)

	
	
	ret = pcap_loop(handle,-1,procesa_paquete,None)
	if ret == -1:
		logging.error('Error al capturar un paquete')
	elif ret == -2:
		logging.debug('pcap_breakloop() llamado')
	elif ret == 0:
		logging.debug('No mas paquetes o limite superado')
	logging.info('{} paquetes procesados'.format(num_paquete))
	logging.info('{} diferencia de tiempo entre el último y el primer paquete capturado'.format(compute_time(first_time, last_time)))
	#TODO si se ha creado un dumper cerrarlo
	if args.interface:
		pcap_dump_close(pdumper)
		pcap_dump_close(pdumper2)

	pcap_close(handle)
	

