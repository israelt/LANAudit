# LANAudit
Herramienta para auditorías LAN

---

##ADVERTENCIA
Esta utilidad es una prueba de concepto para el **proyecto de fin de grado de la UOC 2020/2021 S2**. El creador de esta utilidad se exime de cualquier daño o perjuicio derivado de su uso incorrecto o su uso en redes en producción. Está orientada a la auditoría de redes y su uso se deberá limitar a redes de test o laboratorios virtuales.

La instalación de la función de autoarranque **`enable_autostart.sh`** elimina cualquier otro servicio arrancado mediante el servicio **rc.local** y configura **LANAudit** para su arranque en cada inicio del sistema operativo. Por ello, se recomienda la instalación y el uso de LANAudit en un sistema operativo recién instalado y dedicado a esta tarea. 

No se debe instalar **LANAudit** en sistemas operativos Linux dedicados a tareas de escritorio o servidores. Se recomienda el uso dedicado de un sistema operativo/máquina para el uso de **LANAudit**

---

## REQUERIMIENTOS
- KALI Linux 2021.1 Release (https://www.kali.org/downloads/)

Versiones de 32 y 64 bits para funcionalidades completas y versiones ARM para funcionalidad limitadas sin escáner WEB.


## INSTALACIÓN
Basado en versiones de 32 y 64 bits:

- Se desrcagar y ejecuta **KALI Linux 2021.1**
- Se hace login y desde una ventana de **shell** se cambia a usuario **root** mediante `sudo su`
- En shell de **root** se apunta al directorio **/opt** mediante `cd /opt`
- Se clona el repositorio del proyecto mediante `git clone http://github.com/israelt/lanaudit.git`
- Se apunta al directorio **/opt/lanaudit/install** mediante `cd /opt/lanaudit/install`
- Se actualiza la release de KALI Linux e instalan todos los paquetes necesario en el sistema mediante el comando `sh ./install.sh`
- Una vez finalizada la instalación se puede proceder a ejecutar la aplicación o configurarla para que se lance de forma automática en los próximos arranques del sistema 

**Bloque de código para la instalación:**
```
sudo su
cd /opt
git clone http://github.com/israelt/lanaudit.git
cd /opt/lanaudit/install
sh ./install.sh
```

## USO
En proceso




## AUTOARRANQUE
En proceso

