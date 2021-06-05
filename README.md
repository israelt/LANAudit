# LANAudit
![LANAudit](lanaudit.png)
<h2>Herramienta para auditorías LAN</h2>

---

---

## ADVERTENCIA
Esta utilidad pertenece al **proyecto de fin de grado de la UOC 2020/2021 S2**. El creador de esta utilidad se exime de cualquier daño o perjuicio derivado de su uso incorrecto o su uso en redes en producción. Está orientada a la auditoría de redes y su uso se deberá limitar a redes de test o laboratorios virtuales.

La instalación de la función de auto-arranque `enable_autostart.sh` configura **LANAudit** para su arranque en cada inicio del sistema operativo. Por ello, se recomienda la instalación y el uso de **LANAudit** en un sistema operativo recién instalado y dedicado a esta tarea. 

No se debe instalar **LANAudit** en sistemas operativos Linux dedicados a tareas de escritorio o servidores. Se recomienda el uso dedicado de un sistema operativo/máquina para el uso de **LANAudit**

---

---

## REQUERIMIENTOS
- KALI Linux 2021.1 (64bits) o 2021.2 (64bits) Release (https://www.kali.org/downloads/)

Versiones x86 (64bits) para funcionalidades completas y versiones ARM para funcionalidades limitadas: sin escáner de vulnerabilidades WEB.

---

## INSTALACIÓN

**Las rutas de instalación deben ser las marcadas en este documento:** 
 - `/opt/` para las extensiones
   
 - `/opt/lanaudit` para la aplicación principal

El proceso de instalación para versiones x86 (64bits) es:

- Se descarga y ejecuta **KALI Linux 2021.1** o **KALI Linux 2021.2**
- Se hace login y desde una ventana de **shell** se cambia a usuario **root** mediante `sudo su`
- En shell de **root** se apunta al directorio **/opt** mediante `cd /opt`
- Se clona el repositorio del proyecto mediante `git clone https://github.com/israelt/lanaudit.git`
- Se apunta al directorio **/opt/lanaudit/install** mediante `cd /opt/lanaudit/install`
- Se actualiza la release de **KALI Linux** e instalan todos los paquetes necesarios en el sistema mediante el comando `sh ./install.sh`
- Una vez finalizada la instalación se puede proceder a ejecutar la aplicación o configurarla para que se lance de forma automática en los próximos arranques del sistema.

**Bloque de código para la instalación:**
```
sudo su
cd /opt
git clone https://github.com/israelt/lanaudit.git
cd /opt/lanaudit/install
sh ./install.sh
```
---

## USO

Para lanzar un escaneo con la configuración por defecto se ejecuta el script `/opt/lanaudit/lanaudit.sh`

Se recomienda revisar la configuración del archivo `lanaudit.ini` y la sección de [CONFIGURACIÓN](#CONFIGURACIÓN) de este **README.md** antes de ejecutar un escaneo de la red.

Una vez finalizado el proceso de auditoría se pueden encontrar los ficheros de evidencias en la ruta: `/opt/lanaudit/audits`

Los ficheros de evidencias resumen son los reportes ejecutivos y técnicos en formato *PDF*

El fichero de registro (*log*) de todo el proceso y los registros de cada escáner se encuentran en el mismo directorio y extensión *.log*

---

## CONFIGURACIÓN
La configuración del escáner se debe establecer antes de su ejecución mediante el fichero: `/opt/lanaudit/lanaudit.sh`

Este fichero viene definido por defecto con esta estructura y parámetros:
```
[NETCONFIG]
Mode = auto
Interface = eth0
IP = 10.10.100.200
Mask = 255.255.255.0
IPRange1 = 10.0.0.1/255.255.255.0
IPRange2 = 10.10.10.1/255.255.255.0
IPRange3 = 192.168.0.1/255.255.255.0
IPRange4 = 172.26.0.1/255.255.255.0
IPRange5 = 172.26.10.1/255.255.255.0
[BRUTEFORCE]
Enabled = 1
OnlyCheck = 1
UserFile = ./usernames.list
PowerOff = 0
```

A continuación se detallan los parámetros que se pueden definir en este fichero de configuración:

<h3>[NETCONFIG]</h3>
<h4>Mode = auto</h4>

>Admite las opciones ***auto*** y ***static***
> 
>-	***static***: el sistema configura la interfaz de red seleccionada con la IP y la máscara de red que aparecen en este fichero de configuración.
> 
>-	***auto***: el sistema configura la interfaz de red seleccionada con DHCP. Si no se consiguiera una IP o esta no tuviera conectividad con su puerta de acceso, se intenta la configuración con cada una de las configuraciones IP de los parámetros IPRange de este fichero, de forma secuencial.

<h4>Interface = eth0</h4>

>Define la interfaz de red que se utilizará para realizar la auditoría.

<h4>IP = 172.26.0.1</h4>

>Define la dirección IP que se configurará en la interfaz para `Mode = static`

<h4>Mask = 255.255.255.0</h4>

>Define la máscara de red que se configurará en la interfaz para `Mode = static`

<h4>

IPRange1 = 10.0.0.1/255.255.255.0

IPRange2 = 10.10.10.1/255.255.255.0

IPRange3 = 192.168.0.1/255.255.255.0

IPRange4 = 172.26.0.1/255.255.255.0

IPRange5 = 172.26.10.1/255.255.255.0

</h4>

>Es la configuración IP a utilizar cuando `Mode = auto` y no sea posible obtener una dirección IP con conectividad por DHCP. Se configurará en orden secuencial hasta que el sistema tenga conectividad o se finalice la lista, lo que generará un error de aplicación.

<h3>[BRUTEFORCE]</h3>
<h4>Enabled = 1</h4>

>Indica que la auditoría debe intentar el ataque por fuerza bruta a los puertos TCP: 21(FTP), 22(SSH), 23(TELNET), 389(LDAP), 445(SMB), 3306(MYSQL) y 5900(VNC) 

<h4>OnlyCheck = 1</h4>

>Si se activa el ataque por fuerza bruta solo se realizará con 100 contraseñas por usuario. Es útil si se desea comprobar que el sistema es vulnerable a este tipo de ataques, pero no es necesario conseguir la contraseña, lo que elevaría el tiempo de ejecución

<h4>PowerOff = 0</h4>

>Si se configura a 1 apaga el sistema cuando finaliza la auditoría, en caso contrario al finalizar la auditoría no se realizará ninguna acción 

<h4>UserFile = ./usernames.list</h4>

>Define el diccionario de nombres de usuario a utilizar en los ataques de fuerza bruta. El diccionario de contraseñas es siempre ***rockyou*** `/usr/share/wordlists/rockyou.txt` o su versión generada de 100 registros si **OnlyCheck = 1**

---

## AUTO-ARRANQUE
La instalación de la función de auto-arranque `enable_autostart.sh` añade **LANAudit** para su arranque en cada inicio del sistema operativo mediante la configuración del `init.d` del sistema. Por ello, se recomienda la instalación y el uso de **LANAudit** en un sistema operativo dedicado a la tarea de auditorías de seguridad. 

Para instalar la función de auto-arranque se debe ejecutar con permisos de **root** el siguiente script en el subdirectorio de instalación de **LANAudit**:

`/opt/lanaudit/install/enable_autostart.sh`

Si se reinicia el sistema operativo tras esta instalación se iniciará de forma automática el escáner con los parámetros definidos en el fichero `lanaudit.ini` 


Para desinstalar la función de auto-arranque se debe ejecutar con permisos de **root** el siguiente script en el subdirectorio de instalación de **LANAudit**:

`/opt/lanaudit/install/disable_autostart.sh`

---

## LICENCIA Y RECURSOS UTILIZADOS

**LANAudit** está desarrollado bajo licencia **Creative Commons Reconocimiento-NoComercial-CompartirIgual 3.0 España (CC BY-NC-SA 3.0 ES)** https://creativecommons.org/licenses/by-nc-sa/3.0/es/

**LANAudit** utiliza diferentes herramientas y utilidades libres disponibles para **KALI Linux** y **DEBIAN Linux** como:

- Nmap
  
- Hydra
  
- Nbtscan-unixwiz 

- Weasyprint

- DHCPig

- Impacket

- Snmp-check

- Arachni

El código utilizado en los módulos Python (.py) de este proyecto es desarrollo propio del creador a excepción del módulo `nmaptocsv.py` el cual pertenece a Thomas Debize <tdebize at mail.com> (https://github.com/maaaaz/nmaptocsv)

El logotipo de LANAudit ha sido creado con la herramienta gratuita Hatchful de Shopify (https://hatchful.shopify.com/)

---