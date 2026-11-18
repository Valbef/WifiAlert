Sistema de alerta de conexiones a tu red privada para Linux y Windows.

Permite crear whitelist, guardar dispositivos desconocidos y dispositivos a bloquear desde la misma herramienta.

(El bloqueo de dispositivos debe gestionarse desde la configuracion el router o desde otra herramienta)


Instalacion en linux:

 Requerimientos:

 -Python

 -scapy

 Descarga:

  git clone https://github.com/Valbef/WifiAlert.git

 Abrir desde la terminal: 

  cd WifiAlert

  python WifiAlert.py


========================================================================

Instrucciones de uso:

 1-Seleccionar una de las interfaces Wifi disponibles.

 2-Seleccionar una red detectada o introducirla manualmente con el comando M (por ejemplo ???.???.?.0/24)

 (ver la red con iwconfig y sustituir el ultimo numero por 0/24)

 3-Seleccionaentre modo Manual o Automatico (usa el modo manual para el primer uso para crear la whitelist)

 4-Selecciona el intervalo de tiempo entre escaneos.

 5-Selecciona tu red wifi (Punto de acceso)

 6-Empieza a gestionar tus dispositivos autorizados y desconocidos.

 

 
 

 ·


