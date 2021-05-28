# Realiza los escaneos de SMB a cada host
# Israel Torres Gonzalo
# TFG UOC 2020/2021 S2

import cnmap
import os
from shlex import split
import subprocess
import sqlite3


def scan(mainname, ip):
    # Se definen los parámetros y variables iniciales
    dbname = mainname + '.db'
    mainname = mainname + '.smb_' + ip
    mask = '32'

    # Comienza el escaneo
    vulnerable = 0
    cnmap.portscan(hosts=ip + '/' + mask, ports='445', arguments='-script=smb-vuln-ms17-010', logname=mainname)
    commandraw = 'nmap -p445 -script=smb-vuln-ms17-010 ' + ip

    # Borrado de otros logs y cambio de nombre
    if os.path.exists(mainname + '.gnmap'):
        os.remove(mainname + '.gnmap')
    if os.path.exists(mainname + '.xml'):
        os.remove(mainname + '.xml')
    if os.path.exists(mainname + '.nmap'):
        os.rename(mainname + '.nmap', mainname + '.log')

    # Conversión de datos
    command = ('python3 nmaptocsv.py -i ' + mainname + '.log -f ip-os-protocol-port-service-script')
    command = split(command)
    process = subprocess.Popen(command,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    
    # Parseo de datos a insertar en la base de datos
    while True:
        output = process.stdout.readline()
        if output.strip() == '"IP";"OS";"PROTOCOL";"PORT";"SERVICE";"SCRIPT"':
            output = process.stdout.readline()
            while True:
                if len(output) == 0:
                    break
                if ';' in output.strip():
                    data = output.strip().split(';')
                    for i in range(6):
                        data[i] = data[i].replace('"', '')
                    if len(data[5]) == 0:
                        data[5] = "NO"
                        vulnerable = 0
                    else:
                        data[5] = "SI"
                        vulnerable = 1
                    # Se insertan los datos en la base de datos
                    connection = sqlite3.connect(dbname)
                    cursor = connection.cursor()
                    sql_insert = """INSERT INTO smb (ip, command, vunl, output) VALUES (?,?,?,?);"""
                    registro = (data[0], commandraw, data[5], mainname + '.log')
                    cursor.execute(sql_insert, registro)
                    connection.commit()
                    connection.close()
                output = process.stdout.readline()
        return_code = process.poll()
        if return_code is not None:
            break

    # Devolvemos 1 o 0 dependiendo de si es vulnerable o no
    return vulnerable
