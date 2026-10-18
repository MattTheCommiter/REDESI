# Práctica 1
*Realizada por Álvaro Íñigo Romillo y Matteo Artuñedo González, del grupo 130_1*

A continuación se mencionarán las funcionalidades desarrolladas y las comprobaciones realizadas:

## Normativa de entrega cumplida en su totalidad: Realizado 
Varias relecturas del enunciado y revisión del archivo subido a Moodle.
    
## Recibir tramas Ethernet, realizar comprobaciones y llamar correctamente a la función de callback de nivel superior: Realizado 
    
## Enviar tramas Ethernet correctamente: Realizado.
Como se describe en los puntos posteriores, tanto el envio de tramas Ethernet para mensajes broadcast o protocolo ARP (ambos diferenciados en el codigo con su ETHTYPE) funcionan correctamente, se envian entre los hosts de mininet y son captados por wireshark.

## Imprimir mensajes sobre el protocolo 0x0AA0: Realizado
Cuando se introduce el comando 'm "mensaje"' se lanza un mensaje en broadcast que le llegara a todos los usuarios conectados a la misma red local. Se adjunta la captura de pantalla (Imagenes/Imprimir_mensajes) para comprobar el correcto funcionamiento del envio de mensajes ethernet, ademas de la impresión de los mismos mostrando fecha, segundos y microsegundos, direccion MAC de origen y el texto enviado.

## Enviar correctamente peticiones ARP: Realizado.
Las tramas ARP se envían cuando se introducen los comandos "g" o bien "a <IP>". En ambos casos, se llama a la función ARPResolution, que es la que coordina la resolución ARP y compone y envía la ARP request inicial.Se han aportado capturas (/Imagenes/Envio_de_ARP e Imagenes/Envio_de_ARP2) que demuestran que, tanto en los casos de ARP gratuito como petición ARP a una IP concreta, la request aparece en Wireshark como enviada. En concreto, en las capturas aparecen 3 peticiones realizadas al comenzar el programa, que se corresponden a una petición de ARP gratuita inicial, y otras 3 peticiones ejecutadas con el comando introducido (en el programa, se ejecuta una petición hasta 3 veces en caso de que no se reciba una respuesta)

## Procesar correctamente peticiones ARP recibidas: Realizado
Para probar esta funcionalidad, comprobamos que la ARP request aparecía en la captura de Wireshark del host que la recibía e incluimos un mensaje al final del código de ProcessARPRequest para saber que se había procesado la petición. Esta funcionalidad también queda probada al probar la corrección del próximo apartado. Las capturas correspondientes a este apartado son Imagenes/Recepcion_de_ARP, Imagenes/Recepcion_de_ARP2 y Imagenes/Recepcion_de_ARP3.
## Enviar correctamente respuestas ARP
La captura mostrada en el apartado anterior demuestra que el host que recibe la ARP request envía la respuesta a dicha petición. La nueva captura (Imagenes/Envio_de_Respuesta_ARP) muestra que, efectivamente, el host que había comenzado la resolución ARP en un primer momento recibe la respuesta (aparecen dos respuestas en la captura, la enviada por nuestro programa y la enviada por el sistema operativo).
## Procesar correctamente respuestas ARP
La captura del apartado anterior muestra que el host que envió la petición de ARP procesa la respuesta correctamente e imprime por terminal la dirección MAC del otro host.
## Manejo correcto de la caché ARP
Para probar esta funcionalidad, hemos ejecutado el programa realizando "a 10.0.0.2" desde h1 dos veces consecutivas. Con Wireshark, hemos podido comprobar que solo se realizaban peticiones ARP la primera vez que se ejecutaba el comando, pues en la segunda se leyó el dato de la caché ARP. Además, hemos impreso la caché ARP para asegurarnos de que el dato estaba guardado correctamente. Todo esto se muestra en la captura Imagenes/Procesamiento_de_Respuesta_ARP.
