# Realiza los escaneos de SNMP a cada host
# Israel Torres Gonzalo
# TFG UOC 2020/2021 S2

import cnmap
import os
import subprocess
import sqlite3

scriptdir = (os.path.dirname(os.path.realpath(__file__)))


def scan(mainname, ip):
    # Se definen los parámetros y variables iniciales
    vulnerable = 0
    dbname = mainname + '.db'
    mainname = mainname + '.snmp_' + ip
    mask = '32'

    # Comienza el escaneo
    vulnerable = 0
    cnmap.portscan(hosts=ip + '/' + mask, ports='161',
                   arguments='-sU --script snmp-brute --script-args snmp-brute.communitiesdb=' + scriptdir + '/snmp_common_names.list',
                   logname=mainname)
    commandraw = 'nmap -p161 -sU --script snmp-brute --script-args snmp-brute.communitiesdb=' + scriptdir + '/snmp_common_names.list ' + ip

    # Borrado de otros logs y cambio de nombre
    if os.path.exists(mainname + '.gnmap'):
        os.remove(mainname + '.gnmap')
    if os.path.exists(mainname + '.xml'):
        os.remove(mainname + '.xml')
    if os.path.exists(mainname + '.nmap'):
        os.rename(mainname + '.nmap', mainname + '.log')

    # Se "parsean" de los datos
    openlogfile = open(mainname + '.log', 'r')
    while True:
        output = openlogfile.readline()
        if len(output) == 0:
            openlogfile.close()
            break
        if 'Valid credentials' in output:
            openlogfile.close()
            community = output.replace('|_ ', '').replace(' - Valid credentials', '')
            vulnerable = 1
            break

    # Si es vulnerable se extrae más información
    if vulnerable == 1:
        openlogfile = open(mainname + '.log', 'a+')
        commandraw2 = ('snmp-check ' + ip + ' -p 161 -c ' + community)
        command = commandraw2.split()
        subprocess.call(command, stdout=openlogfile)
        openlogfile.close()

    # Se insertan los datos en la base de datos
    if vulnerable == 1:
        vuln = 'SI'
    else:
        vuln = 'NO'
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    sql_insert = """INSERT INTO snmp (ip, command, vunl, output) VALUES (?,?,?,?);"""
    registro = (ip, commandraw, vuln, mainname + '.log')
    cursor.execute(sql_insert, registro)
    connection.commit()
    connection.close()

    # Se devuelve 1 o 0 dependiendo de si es vulnerable o no
    return vulnerable
