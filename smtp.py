# Realiza los escaneos de SMTP a cada host
# Israel Torres Gonzalo
# TFG UOC 2020/2021 S2

import subprocess
import os
import sqlite3

scriptdir = (os.path.dirname(os.path.realpath(__file__)))


def scan(onlyname, ip, port):
    # Se definen los parámetros y variables iniciales y definen los ficheros de logs necesarios
    vulnerable = 0
    logfile = scriptdir + '/audits/' + onlyname + '.smtp_' + ip + '.log'

    # Comienza el escaneo mediante la invocacion de un script sh propio con volcado a los ficheros anteriormente 
    # definidos 
    commandraw = '{ echo "HELO"; echo "MAIL"; echo "QUIT"; sleep 1; } | telnet ' + ip + ' ' + port
    command = ('sudo sh ' + scriptdir + '/smtp_script.sh ' + ip + ' ' + port + ' ' + logfile)
    command = command.split()
    subprocess.call(command)

    # Se determina si es vulnerable o no por la salida del stdout del comando
    openlogfile = open(logfile)
    while True:
        output = openlogfile.readline()
        if len(output) == 0:
            openlogfile.close()
            vulnerable = 0
            break
        if '5.7.3' in output:
            openlogfile.close()
            vulnerable = 0
            break
        if '5.5.4' in output:
            openlogfile.close()
            vulnerable = 1
            break

    # Se insertan los datos en la base de datos
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    sql_insert = """INSERT INTO smtp (ip, command, vunl, output) VALUES (?,?,?,?);"""
    if vulnerable == 1:
        registro = (ip, commandraw, 'SI', logfile)
    if vulnerable == 0:
        registro = (ip, commandraw, 'NO', logfile)
    cursor.execute(sql_insert, registro)
    connection.commit()
    connection.close()

    # Devolvemos 1 o 0 dependiendo de si es vulnerable o no
    return vulnerable
