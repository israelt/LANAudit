# Realiza los escaneos de cuentas de invitados activas en sistemas Windows
# Israel Torres Gonzalo
# TFG UOC 2020/2021 S2

from shlex import split
from shutil import copyfile
import subprocess
import os
import sqlite3

scriptdir = (os.path.dirname(os.path.realpath(__file__)))


def scan(onlyname, ip):
    # Se definen los parámetros y variables iniciales y se abren los ficheros de log y errores necesarios
    vulnerable = 0
    if os.path.isfile(scriptdir + '/audits/' + onlyname + '.guest.error'):
        os.remove(scriptdir + '/audits/' + onlyname + '.guest.error')
    logfile = open(scriptdir + '/audits/' + onlyname + '.guest_' + ip + '.log', 'w+')
    errorfile = open(scriptdir + '/audits/' + onlyname + '.guest.error', 'w+')

    # Comienza el escaneo mediante comando con volcado a los ficheros anteriormente definidos
    commandraw = ('hydra -l guest -p guest -s 445 smb://' + ip)
    command = commandraw.split()
    subprocess.call(command, stdout=logfile, stderr=errorfile)
    logfile.close()
    errorfile.close()

    # Se determina si es vulnerable o no por la salida stderr del comando
    if os.path.isfile(scriptdir + '/audits/' + onlyname + '.guest.error'):
        openlogfile = open(scriptdir + '/audits/' + onlyname + '.guest.error', 'r')
        while True:
            output = openlogfile.readline()
            if len(output) == 0:
                openlogfile.close()
                os.remove(scriptdir + '/audits/' + onlyname + '.guest.error')
                vulnerable = 0
                break
            if 'Anonymous success' in output:
                openlogfile.close()
                vulnerable = 1
                copyfile(scriptdir + '/audits/' + onlyname + '.guest.error',
                         scriptdir + '/audits/' + onlyname + '.guest_' + ip + '.log')
                os.remove(scriptdir + '/audits/' + onlyname + '.guest.error')
                break

    # Se insertan los datos en la base de datos
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    sql_insert = """INSERT INTO guest (ip, command, vunl, output) VALUES (?,?,?,?);"""
    if vulnerable == 1:
        registro = (ip, commandraw, 'SI', scriptdir + '/audits/' + onlyname + '.guest_' + ip + '.log')
    if vulnerable == 0:
        registro = (ip, commandraw, 'NO', scriptdir + '/audits/' + onlyname + '.guest_' + ip + '.log')
    cursor.execute(sql_insert, registro)
    connection.commit()
    connection.close()

    # Devolvemos 1 o 0 dependiendo de si es vulnerable o no
    return vulnerable
