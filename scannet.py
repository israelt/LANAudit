# Utiliza NMAP para localizar hosts en la red
# Israel Torres Gonzalo
# TFG UOC 2020/2021 S2

import cnmap
from shlex import split
import subprocess
import sqlite3


def scannmap(network, mask, mainname):
    # Comienza el escaneo
    cnmap.portscan(hosts=network + '/' + mask, arguments='-Pn -sV -O ', logname=mainname)

    # Conversión de datos
    command = ('python3 nmaptocsv.py -i ' + mainname + '.gnmap -f ip-os-protocol-port-service-version')
    command = split(command)
    process = subprocess.Popen(command,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    
    # Parseo de datos a BD
    while True:
        output = process.stdout.readline()
        print(output.strip())
        if output.strip() == '"IP";"OS";"PROTOCOL";"PORT";"SERVICE";"VERSION"':
            output = process.stdout.readline()
            while True:
                if len(output) == 0:
                    break
                if ';' in output.strip():
                    data = output.strip().split(';')
                    print(data)
                    # Se insertan los datos en la base de datos
                    dbname = mainname + '.db'
                    connection = sqlite3.connect(dbname)
                    cursor = connection.cursor()
                    sql_insert = """INSERT INTO nmap (ip, os, protocol, port, service, version) VALUES (?,?,?,?,?,?);"""
                    registro = (data[0].replace('"', ''), data[1].replace('"', ''), data[2].replace('"', ''), data[3].replace('"', ''), data[4].replace('"', ''), data[5].replace('"', ''))
                    cursor.execute(sql_insert, registro)
                    connection.commit()
                    connection.close()
                output = process.stdout.readline()
        return_code = process.poll()
        if return_code is not None:
            print('RETURN CODE', return_code)
            for output in process.stdout.readlines():
                null
                print(output.strip())
            break

    return 0
