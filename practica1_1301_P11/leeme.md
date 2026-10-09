# Práctica 1
*Realizada por Álvaro Íñigo Romillo y Matteo Artuñedo González, del grupo 130_1*

A continuación se mencionarán las funcionalidades desarrolladas y las comprobaciones realizadas:

## Normativa de entrega cumplida en su totalidad: Realizado 
Varias relecturas del enunciado y revisión del archivo subido a Moodle.
    
## Contar paquetes de una traza: Realizado 
Se ha comprobado que el número de paquete que muestra nuestro programa coincide con el que indica Wireshark. Así se demuestra en el archivo 'captura_n_paquetes_traza.png', donde se contrastan los paquetes contados por nuestro programa con los contados por Wireshark dada la misma traza.
También se ha probado que, al indicar de forma explícita el número de paquetes a capturar, el resultado de paquetes contados sea coincidente.
    
## Contar paquetes de la interfaz de red: Realizado.
Se ha comprobado que el número de paquete que muestra nuestro programa coincide con el que indica Wireshark. Así se demuestra en el archivo 'captura_n_paquetes_interfaz.png', donde se contrasta el número de paquetes contado por nuestro programa durante la captura en tiempo real con los contados por Wireshark dadas las trazas creadas.
También se ha probado que, al indicar de forma explícita el número de paquetes a capturar, el resultado de paquetes contados sea coincidente.
    

## Almacenar en una traza el tráfico capturado en vivo: Realizado
Se ha comprobado que todos los bytes de la traza capturada coinciden con lo que indica Wireshark en un conjunto diverso de paquetes.
    
## Calcular tiempo entre primer y último paquete: Realizado.
Se ha comprobado que, dada una traza, la diferencia marcada por nuestro programa y la que podemos calcular a mano a partir de los datos de Wireshark coinciden.

## Imprimir los N primeros bytes de un paquete y validarlo con Wireshark (captura de pantalla): Realizado 
Se imprimen correctamente los bytes especificados. Se observa esto en el archivo 'practica1captura.png', donde se imprimen los primeros 33 bytes del paquete y se ve que coinciden con los mostrados en Wireshark.
