# Realiza los escaneos de RPC a cada host
# Israel Torres Gonzalo
# TFG UOC 2020/2021 S2

from shlex import split
import subprocess
import os
import sqlite3

scriptdir = (os.path.dirname(os.path.realpath(__file__)))


def scan(onlyname, ip):
    # Se definen los parámetros, variables iniciales y fichero de log para stdout
    vulnerable = 0
    logfile = open(scriptdir + '/audits/' + onlyname + '.rpc_' + ip + '.log', 'a+')

    # Comienza el escaneo con volcado de salida a consola redirigido al fichero de log
    commandraw = ('sudo python3 /opt/impacket-0.9.22/examples/rpcdump.py ' + ip)
    command = split(commandraw)
    process = subprocess.Popen(command,
                           stdout=subprocess.PIPE,
                           universal_newlines=True)

    # Se revisa el fichero de log para determinar si el host es vulnerable
    while True:
        output = process.stdout.readline()
        logfile.write(output)
        print(output.strip())
        if '[*] Received ' in output.strip():
            vulnerable = 1
            logfile.close()
            break
        if '[*] No endpoints found.' in output.strip():
            vulnerable = 0
            logfile.close()
            break

    # Se insertan los datos en la base de datos
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    sql_insert = """INSERT INTO rpc (ip, command, vunl, output) VALUES (?,?,?,?);"""
    if vulnerable == 1:
        registro = (ip, commandraw, 'SI', scriptdir + '/audits/' + onlyname + '.rpc_' + ip + '.log')
    if vulnerable == 0:
        registro = (ip, commandraw, 'NO', scriptdir + '/audits/' + onlyname + '.rpc_' + ip + '.log')
    cursor.execute(sql_insert, registro)
    connection.commit()
    connection.close()

    # Devolvemos 1 o 0 dependiendo de si es vulnerable o no
    return vulnerable
