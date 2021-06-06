# LANAudit MAIN
# Israel Torres Gonzalo
# TFG UOC 2020/2021 S2

from datetime import datetime
import os
import logging
import sqlite3
import createtables
import ipsearch
import ipconfig
import readini
import scannet
import dhcp
import netbios
import smb
import smbghost
import rpc
import snmp
import smtp
import guest
import web
import bruteforce
import reporttec
import reportexe


### FUNCIONES ###

# Define el nombre y el formato de los ficheros de logs
def initLog(logFile):
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        # level=logging.INFO,
        level=logging.DEBUG,
        datefmt='%Y-%m-%d %H:%M:%S',
        filename=logFile,
        encoding='utf-8')

    logging.info("LOGGER: Inicio de LOG")


# Función para cambio de representación de máscara de red a cidr
def mask_cidr(mask):
    return sum([bin(int(bits)).count("1") for bits in mask.split(".")])


# Función para guardar los hosts descubiertos en NMAP en una lista
def gethosts(dbname, interface='eth0', port='all', protocol='tcp'):
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    if port == 'all':
        cursor.execute("SELECT DISTINCT ip FROM nmap ORDER BY 1;")
    else:
        cursor.execute("SELECT DISTINCT ip FROM nmap WHERE protocol = ? AND port = ? ORDER BY 1;", (protocol, port))
    hosts = [item[0] for item in cursor.fetchall()]
    connection.close()
    mylocalip = ipconfig.getLocalIP(interface)
    if mylocalip in hosts:
        hosts.remove(mylocalip)
    return hosts


# Especifica la configuración por rangos
def rangeConf():
    audit = 0
    totalranges = readini.manyRanges()
    totalranges = int(totalranges)
    totalranges = totalranges + 1
    if totalranges == 0:
        logging.info("EXIT: No hay rangos configurados pruebe con otra configuracion IP")
        raise SystemExit('Error: No hay rangos configurados pruebe con otra configuracion IP')

    for i in range(1, totalranges):
        j = str(i)
        ip = readini.readConfig('IPRange' + j).split('/')[0]
        ip = str(ip)
        mask = readini.readConfig('IPRange' + j).split('/')[1]
        mask = str(mask)
        logging.info("IP: IP " + ip + " y mascara " + mask + " asignada por rango " + j)
        ipconfig.ipConfig(ip, interface, mask)
        print(ip)
        searchip = ipsearch.ipSearch(interface, dbname)
        if not searchip == -1:
            ipconfig.ipConfig(searchip, interface, mask)
            logging.info("IP: La IP asignada por rango tiene conectividad")
            logging.info("SCAN: Iniciando auditoria con IP " + ip + " y mascara " + mask)
            audit = 1
            break
        else:
            logging.info("IP: La IP asignada por rango NO tiene conectividad")
    if audit == 0:
        logging.info("EXIT: No hay conectividad con la configuracion de ningun rango")
        raise SystemExit('Error: No hay conectividad con la configuracion de ningun rango')
    else:
        # Se lanza función de auditoria con IP descubierta por RANGOS
        auditScan(searchip, mask)


# Auditoria Escaneo de IP
def auditScan(ip, mask):
    # Se convierte la mascara al formato CIDR
    mask = str(mask_cidr(mask))
    # Se guarda la configuración como registro en la bd
    ipconfig.saveConfig(onlyname, ip, mask, interface, mode, brute, bruteonlycheck, brutefile)
    print('Lanzando NMAP con IP ' + ip + ' a rango de red ' + mask)
    logging.info('SCAN: Lanzando NMAP con IP ' + ip + ' a rango de red ' + mask)
    # Modulo encargado de escaneo general de hosts
    if scannet.scannmap(ip, mask, mainname) == 0:
        print('SCAN HOSTS: Lista de HOSTS conseguida')
        logging.info('SCAN HOSTS: Lista de HOSTS conseguida')
        # Se guarda la lista de hosts conseguida en el nmap
        hosts = gethosts(dbname, interface)
        out_str = ' '
        print('SCAN HOSTS: ' + out_str.join(hosts))
        logging.info('SCAN HOSTS: ' + out_str.join(hosts))
    else:
        logging.info('ERROR: Error en proceso AuditScan')
        raise SystemExit('Error: Error en proceso AuditScan')
    # Iniciando módulos encargados de escaneos a petición
    # Escaneando DHCP
    print('SCAN DHCP: Escaneando vulnerabilidades DHCP')
    logging.info('SCAN DHCP: Escaneando vulnerabilidades DHCP')
    if dhcp.scan(onlyname, interface) == 1:
        print('SCAN DHCP: Red Vulnerable a ataque DHCP EXHAUSTED')
        logging.info('SCAN DHCP: Red Vulnerable a ataque DHCP EXHAUSTED')
    else:
        print('SCAN DHCP: Red NO vulnerable a ataque DHCP EXHAUSTED o no tiene IPs libres')
        logging.info('SCAN DHCP: Red NO vulnerable a ataque DHCP EXHAUSTED o no tiene IPs libres')
    # Escaneando NETBIOS
    print('SCAN NETBIOS: Escaneando vulnerabilidades NETBIOS')
    logging.info('SCAN NETBIOS: Escaneando vulnerabilidades NETBIOS')
    for i in hosts:
        if netbios.scan(onlyname, i) == 1:
            print('SCAN NETBIOS: El host ' + i + ' es Vulnerable a ataque NETBIOS')
            logging.info('SCAN NETBIOS: El host ' + i + ' es Vulnerable a ataque NETBIOS')
        else:
            print('SCAN NETBIOS: El host ' + i + ' NO es vulnerable a ataque NETBIOS')
            logging.info('SCAN NETBIOS: El host ' + i + ' NO es vulnerable a ataque NETBIOS')
    # Escaneando SMB
    print('SCAN SMB: Escaneando vulnerabilidades SMB')
    logging.info('SCAN SMB: Escaneando vulnerabilidades SMB')
    for i in hosts:
        if smb.scan(mainname, i) == 1:
            print('SCAN SMB: El host ' + i + ' es Vulnerable a ataque SMB v1')
            logging.info('SCAN SMB: El host ' + i + ' es Vulnerable a ataque SMB v1')
        else:
            print('SCAN SMB: El host ' + i + ' NO es vulnerable a ataque SMB v1')
            logging.info('SCAN SMB: El host ' + i + ' NO es vulnerable a ataque SMB v1')
        if smbghost.scan(mainname, i) == 1:
            print('SCAN SMB: El host ' + i + ' es Vulnerable a ataque SMB GHOST')
            logging.info('SCAN SMB: El host ' + i + ' es Vulnerable a ataque SMB GHOST')
        else:
            print('SCAN SMB: El host ' + i + ' NO es vulnerable a ataque SMB GHOST')
            logging.info('SCAN SMB: El host ' + i + ' NO es vulnerable a ataque SMB GHOST')
    # Escaneando RPC
    print('SCAN RPC: Escaneando vulnerabilidades RPC')
    logging.info('SCAN RPC: Escaneando vulnerabilidades RPC')
    for i in hosts:
        if rpc.scan(onlyname, i) == 1:
            print('SCAN RPC: El host ' + i + ' es Vulnerable a ataque RPC')
            logging.info('SCAN RPC: El host ' + i + ' es Vulnerable a ataque RPC')
        else:
            print('SCAN RPC: El host ' + i + ' NO es vulnerable a ataque RPC')
            logging.info('SCAN RPC: El host ' + i + ' NO es vulnerable a ataque RPC')
    # Escaneando SNMP
    print('SCAN SNMP: Escaneando vulnerabilidades SNMP')
    logging.info('SCAN SNMP: Escaneando vulnerabilidades SNMP')
    for i in hosts:
        if snmp.scan(mainname, i) == 1:
            print('SCAN SNMP: El host ' + i + ' es Vulnerable a ataque SNMP')
            logging.info('SCAN SNMP: El host ' + i + ' es Vulnerable a ataque SNMP')
        else:
            print('SCAN SNMP: El host ' + i + ' NO es vulnerable a ataque SNMP')
            logging.info('SCAN SNMP: El host ' + i + ' NO es vulnerable a ataque SNMP')
    # Escaneando SMTP
    """
    ############################################################################
    hosts.clear()
    hosts = gethosts(dbname, interface, '25', 'tcp')
    morehosts = gethosts(dbname, interface, '80', 'tcp')
    if len(morehosts) == 0: morehosts.clear()
    if len(morehosts) == 1: hosts.append(morehosts)
    if len(morehosts) > 1: hosts.extend(morehosts)
    out_str = ' '
    print('SCAN SMTP HOSTS: ' + out_str.join(hosts))
    logging.info('SCAN SMTP HOSTS: ' + out_str.join(hosts))
    ############################################################################
    """
    hosts.clear()
    hosts = gethosts(dbname, interface, '25', 'tcp')
    if len(hosts) == 0:
        print('SCAN SMTP: No se encuentran servidores de correo en el puerto TCP25')
        logging.info('SCAN SMTP: No se encuentran servidores de correo en el puerto TCP25')
    else:
        print('SCAN SMTP: Escaneando vulnerabilidades SMTP puerto TCP25')
        logging.info('SCAN SMTP: Escaneando vulnerabilidades SMTP puerto TCP25')
    for i in hosts:
        if smtp.scan(onlyname, i, '25') == 1:
            print('SCAN SMTP: El host ' + i + ' es Vulnerable a ataque SMTP puerto TCP25')
            logging.info('SCAN SMTP: El host ' + i + ' es Vulnerable a ataque SMTP puerto TCP25')
        else:
            print('SCAN SMTP: El host ' + i + ' NO es vulnerable a ataque SMTP puerto TCP25')
            logging.info('SCAN SMTP: El host ' + i + ' NO es vulnerable a ataque SMTP puerto TCP25')
    hosts.clear()
    hosts = gethosts(dbname, interface, '587', 'tcp')
    if len(hosts) == 0:
        print('SCAN SMTP: No se encuentran servidores de correo en el puerto TCP587')
        logging.info('SCAN SMTP: No se encuentran servidores de correo en el puerto TCP587')
    else:
        print('SCAN SMTP: Escaneando vulnerabilidades SMTP puerto TCP587')
        logging.info('SCAN SMTP: Escaneando vulnerabilidades SMTP puerto TCP587')
        for i in hosts:
            if smtp.scan(onlyname, i, '587') == 1:
                print('SCAN SMTP: El host ' + i + ' es Vulnerable a ataque SMTP puerto 587')
                logging.info('SCAN SMTP: El host ' + i + ' es Vulnerable a ataque SMTP puerto TCP587')
            else:
                print('SCAN SMTP: El host ' + i + ' NO es vulnerable a ataque SMTP puerto TCP587')
                logging.info('SCAN SMTP: El host ' + i + ' NO es vulnerable a ataque SMTP puerto TCP587')
    # Escaneando cuentas de invitado
    hosts.clear()
    hosts = gethosts(dbname, interface, '445', 'tcp')
    if len(hosts) == 0:
        print('SCAN GUEST: No se encuentran servidores Windows con puerto 445 abierto')
        logging.info('SCAN GUEST: No se encuentran servidores Windows con puerto 445 abierto')
    else:
        print('SCAN GUEST: Escaneando cuentas de invitado activas')
        logging.info('SCAN GUEST: Escaneando cuentas de invitado activas')
    for i in hosts:
        if guest.scan(onlyname, i) == 1:
            print('SCAN GUEST: El host ' + i + ' tiene cuenta de invitado activa en Windows')
            logging.info('SCAN GUEST: El host ' + i + ' tiene cuenta de invitado activa en Windows')
        else:
            print('SCAN GUEST: El host ' + i + ' NO tiene cuenta de invitado activa en Windows')
            logging.info('SCAN GUEST: El host ' + i + ' NO tiene cuenta de invitado activa en Windows')
    # Escaneando de servicios web
    if '64' in os.uname()[2]:
        hosts.clear()
        hosts = gethosts(dbname, interface, '80', 'tcp')
        if len(hosts) == 0:
            print('SCAN WEB: No se encuentran servidores WEB HTTP')
            logging.info('SCAN WEB: No se encuentran servidores WEB HTTP')
        else:
            for i in hosts:
                print('SCAN WEB: Escaneando vulnerabilidades WEB de HTTP://' + ip)
                logging.info('SCAN WEB: Escaneando vulnerabilidades WEB de HTTP://' + ip)
                if web.scan(onlyname, i, '80') == 0:
                    print('SCAN WEB: Escaner web del host HTTP://' + i + ' finalizado correctamente')
                    logging.info('SCAN WEB: Escaner web del host HTTP://' + i + ' finalizado correctamente')
        hosts.clear()
        hosts = gethosts(dbname, interface, '443', 'tcp')
        if len(hosts) == 0:
            print('SCAN WEB: No se encuentran servidores WEB HTTPS')
            logging.info('SCAN WEB: No se encuentran servidores WEB HTTPS')
        else:
            for i in hosts:
                print('SCAN WEB: Escaneando vulnerabilidades WEB de HTTPS://' + ip)
                logging.info('SCAN WEB: Escaneando vulnerabilidades WEB de HTTPS://' + ip)
                if web.scan(onlyname, i, '443') == 0:
                    print('SCAN WEB: Escaner web del host HTTPS://' + i + ' finalizado correctamente')
                    logging.info('SCAN WEB: Escaner web del host HTTPS://' + i + ' finalizado correctamente')
    else:
        print('SCAN WEB: El sistema hardware utilizado no soporta el escaner web')
        logging.info('SCAN WEB: El sistema hardware utilizado no soporta el escaner web')
    # Escaneo por fuerza bruta
    if brute == '1':
        services = ['21', '22', '23', '389', '445', '3306', '5900']
        for i in services:
            hosts.clear()
            hosts = gethosts(dbname, interface, i, 'tcp')
            if len(hosts) == 0:
                print('SCAN BRUTEFORCE: No se encuentran servidores con puerto ' + i + ' a la escucha')
                logging.info('SCAN BRUTEFORCE: No se encuentran servidores con puerto ' + i + ' a la escucha')
            else:
                for j in hosts:
                    print('SCAN BRUTEFORCE: Efectuando ataque bruteforce contra puerto ' + i + ' en IP ' + j)
                    logging.info('SCAN BRUTEFORCE: Efectuando ataque bruteforce contra puerto ' + i + ' en IP ' + j)
                    if bruteforce.scan(onlyname, j, i, brutefile, bruteonlycheck) == 0:
                        print('SCAN BRUTEFORCE: Finalizado ataque bruteforce contra puerto ' + i + ' en IP ' + j)
                        logging.info('SCAN BRUTEFORCE: Finalizado ataque bruteforce contra puerto ' + i + ' en IP ' + j)
                    else:
                        print('SCAN BRUTEFORCE: Error en el ataque bruteforce contra puerto ' + i + ' en IP ' + j)
                        logging.info(
                            'SCAN BRUTEFORCE: Error en el  ataque bruteforce contra puerto ' + i + ' en IP ' + j)
    else:
        print('SCAN BRUTEFORCE: Escaneo de ataques de fuerza bruta desactivado')
        logging.info('SCAN BRUTEFORCE: Escaneo de ataques de fuerza bruta desactivado')
    # Fin de escaneos
    print('SCAN END: Se han finalizado los escaneres de vulnerabilidades')
    logging.info('SCAN END: Se han finalizado los escaneres de vulnerabilidades')
    # Generando reporte ejecutivo
    print('REPORTES: Iniciando reporte ejecutivo')
    logging.info('REPORTES: Iniciando reporte ejecutivo')
    if reportexe.do(onlyname, brute) == 0:
        print('REPORTES: Reporte ejecutivo fizalizado')
        logging.info('REPORTES: Reporte ejecutivo fizalizado')
    else:
        print('REPORTES ERROR: Error en la generación del reporte ejecutivo')
        logging.info('REPORTES ERROR: Error en la generación del reporte ejecutivo')
    # Generando reporte técnico
    print('REPORTES: Iniciando reporte tecnico')
    logging.info('REPORTES: Iniciando reporte tecnico')
    if reporttec.do(onlyname, brute) == 0:
        print('REPORTES: Reporte tecnico fizalizado')
        logging.info('REPORTES: Reporte tecnico fizalizado')
    else:
        print('REPORTES ERROR: Error en la generación del reporte tecnico')
        logging.info('REPORTES ERROR: Error en la generación del reporte tecnico')
    # Fin de proceso de auditoria

### FIN DE FUNCIONES ###


### EJECUCION ###

# Configura el nombre de los ficheros de análisis utilizando la fecha y hora para evitar duplicados y dejar evidencia
path = "./audits"
try:
    os.mkdir(path)
except OSError:
    print("CONFIG: Ya existe la carpeta " + path)
now = datetime.now()
onlyname = now.strftime("%Y%m%d_%H%M%S")
mainname = './audits/' + now.strftime("%Y%m%d_%H%M%S")
dbname = './audits/' + now.strftime("%Y%m%d_%H%M%S") + '.db'
logname = './audits/' + now.strftime("%Y%m%d_%H%M%S") + '.log'

# Se inicia el log
initLog(logname)

# Se lee el fichero de configuración
interface = 'eth0'
mode = 'auto'
brute = '0'
brutefile = ''
interface = (readini.readConfig('Interface'))
logging.info("CONFIG: Se elige la interfaz " + interface)
mode = (readini.readConfig('Mode'))
logging.info("CONFIG: Se elige el modo " + mode)
brute = (readini.readBrute('Enabled'))
logging.info("CONFIG: Modo Bruteforce activado: " + brute)
bruteonlycheck = (readini.readBrute('OnlyCheck'))
logging.info("CONFIG: Modo Bruteforce Solo Prueba activado: " + brute)
brutefile = (readini.readBrute('UserFile'))
logging.info("CONFIG: Modo Bruteforce usando fichero de nombres de usuario: " + brutefile)
ispoweroff = (readini.readBrute('PowerOff'))
logging.info("CONFIG: El apagado automatico esta en modo : " + ispoweroff)

# Se crean las tablas necesarias en la base de datos
print('INIT: Creando tablas necesarias en SQLite')
logging.info('INIT: Creando tablas necesarias en SQLite')
createtables.maintables(dbname)

# Comienza la configuración IP
# Proceso AUTO = DHCP o por RANGOS
if mode == 'auto':
    logging.info("IP: Probando configuracion DHCP")
    # Se comprueba si DHCP asigna direccion
    myip = ipconfig.ipConfig("dynamic", interface)
    if not myip == -1:
        logging.info("IP: DHCP asignado " + myip)
        # Se comprueba conectividad
        searchip = ipsearch.ipSearch(interface, dbname)
        if not searchip == -1:
            logging.info("IP: La IP asignada tiene conectividad")
            mask = ipconfig.getLocalMask(interface)
            logging.info("SCAN: Iniciando auditoria con IP " + myip + " y mascara " + mask)
            # Se lanza función de auditoria con IP DHCP
            auditScan(myip, mask)
        else:
            logging.info("IP: La IP asignada NO tiene conectividad")
            logging.info("IP: Se inicia busqueda por rangos")
            # Se intenta configuración sin IP fija ni DHCP por rangos de IP en fichero ini
            rangeConf()
    else:
        print('No se asigna IP')
        logging.info("IP: DHCP NO asignada IP")
        logging.info("IP: Se inicia busqueda por rangos")
        # Se intenta configuración sin IP fija ni DHCP por rangos de IP en fichero ini
        rangeConf()

# Proceso IP ESTÁTICA
if mode == 'static':
    ip = '10.10.10.1'
    mask = '255.255.0.0'
    ip = (readini.readConfig('IP'))
    mask = (readini.readConfig('Mask'))
    myip = ipconfig.ipConfig(ip, interface, mask)
    if not myip == -1:
        logging.info("IP: Asignada IP manualmente " + myip)
        # Se comprueba conectividad
        searchip = ipsearch.ipSearch(interface, dbname)
        if not searchip == -1:
            print(myip)
            logging.info("IP: La IP asignada manualmente tiene conectividad")
            logging.info("SCAN: Iniciando Auditoria de la red")
            # Se lanza función de auditoria con IP FIJA
            auditScan(ip, mask)
        else:
            logging.info("IP: La IP asignada manualmente NO tiene conectividad")
            logging.info("EXIT: Pruebe con otra configuracion IP")
            raise SystemExit('Error: No hay conectividad con la configuracion IP estatica')

print('LOGGER: Fin de LOG')
logging.info('LOGGER: Fin de LOG')
if ispoweroff == '1': os.system("shutdown now -P")
