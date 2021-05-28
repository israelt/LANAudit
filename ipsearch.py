# Busca IPs activas en la red para buscar un probable rango de red
# Israel Torres Gonzalo
# TFG UOC 2020/2021 S2

import subprocess
import time
from shlex import split
import sqlite3
import ipaddress
import findnth


# Función principal del módulo
def ipSearch(interface='eth0', dbname='pruebas.db'):
    makeBroadcast(interface)
    time.sleep(5)
    ettercap(interface, dbname)
    myIP = getRange(dbname)
    return myIP


# Realiza un ping a la dirección de broadcast de la interfaz definida para forzar paquetes a escanear
def makeBroadcast(interface='eth0'):
    command = ('ping -I ' + str(interface) + ' -b 255.255.255.255')
    command = split(command)
    process = subprocess.Popen(command,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)


# Realiza un escaner de la interfaz de red buscando IP activas para conseguir el direccionamiento de la red
def ettercap(interface='eth0', dbname='pruebas.db'):
    # Se inicia la búsqueda de hots
    command = ('timeout 60 ettercap -i ' + str(interface) + ' -Tq -s lq')
    command = split(command)
    process = subprocess.Popen(command,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    while True:
        output = process.stdout.readline()
        if output.strip() == 'Hosts list:':
            output = process.stdout.readline()
            while output.strip() != 'Closing text interface...':
                # Se parsean los datos
                if ')' in output.strip():
                    data = output.strip().split(')')[1].removeprefix("\t")
                    ip, mac = data.split('\t')
                    print(ip, mac)
                    # Se insertan los datos en la BBDD
                    connection = sqlite3.connect(dbname)
                    cursor = connection.cursor()
                    sql_insert = """INSERT INTO ipsearch (ip, mac) VALUES (?,?);"""
                    registro = (ip, mac)
                    cursor.execute(sql_insert, registro)
                    connection.commit()
                    connection.close()
                output = process.stdout.readline()
        return_code = process.poll()
        if return_code is not None:
            for output in process.stdout.readlines():
                null
                print(output.strip())
            break


# Obtiene el rango de las IPs encontradas y elige una dirección que aparentemente no esté utilizada
def getRange(dbname='pruebas.db'):
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    sql_select = """SELECT ip FROM ipsearch ORDER BY 1;"""
    cursor.execute(sql_select)
    iplist = cursor.fetchall()
    assert isinstance(iplist, object)
    print("Numero de IPS:  ", len(iplist))
    # Se sale de la función con -1 si no se ha detectado anteriormente ninguna IP
    if len(iplist) == 0:
        return -1
    for i in range(0, len(iplist)):
        iplist[i] = "".join(iplist[i]).removesuffix(",")
    for i in range(0, len(iplist)):
        oneip = iplist[i]
        result = findnth.find_nth(oneip, '.', 3)
        defaultgtw = oneip[0:result] + '.1'
        oneip = oneip[0:result] + '.0'
        if ipaddress.ip_address(oneip).is_private:
            break
    net = ipaddress.IPv4Network(oneip + '/24').hosts()
    for addr in net:
        saddr = str(addr)
        if not saddr in iplist:
            if not saddr == defaultgtw:
                return saddr
