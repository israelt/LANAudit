# Realiza los escaneos de NETBIOS a cada host
# Israel Torres Gonzalo
# TFG UOC 2020/2021 S2

from shutil import copyfile
import subprocess
import os
import sqlite3

scriptdir = (os.path.dirname(os.path.realpath(__file__)))


def scan(onlyname, ip):
    # Se definen los parámetros y variables iniciales y se abren los ficheros de log y errores necesarios
    vulnerable = 0
    if os.path.isfile(scriptdir + '/audits/' + onlyname + '.netbios.error'):
        os.remove(scriptdir + '/audits/' + onlyname + '.netbios.error')
    logfile = open(scriptdir + '/audits/' + onlyname + '.netbios_' + ip + '.log', 'a+')
    errorfile = open(scriptdir + '/audits/' + onlyname + '.netbios.error', 'w+')

    # Comienza el escaneo mediante comando con volcado a los ficheros anteriormente definidos
    commandraw = ('sudo nbtscan-unixwiz -v -f -P ' + ip)
    command = commandraw.split()
    subprocess.call(command, stdout=logfile, stderr=errorfile)
    logfile.close()
    errorfile.close()

    # Se determina si es vulnerable o no por la salida del stderr del comando
    if os.stat(scriptdir + '/audits/' + onlyname + '.netbios.error').st_size == 0:
        os.remove(scriptdir + '/audits/' + onlyname + '.netbios.error')
        vulnerable = 1
    else:
        copyfile(scriptdir + '/audits/' + onlyname + '.netbios.error', scriptdir + '/audits/' + onlyname + '.netbios_' + ip + '.log')
        vulnerable = 0

    # Se insertan los datos en la base de datos
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    sql_insert = """INSERT INTO netbios (ip, command, vunl, output) VALUES (?,?,?,?);"""
    if vulnerable == 1:
        registro = (ip, commandraw, 'SI', scriptdir + '/audits/' + onlyname + '.netbios_' + ip + '.log')
    if vulnerable == 0:
        registro = (ip, commandraw, 'NO', scriptdir + '/audits/' + onlyname + '.netbios_' + ip + '.log')
    cursor.execute(sql_insert, registro)
    connection.commit()
    connection.close()

    # Se devuelve 1 o 0 dependiendo de si es vulnerable o no
    return vulnerable
