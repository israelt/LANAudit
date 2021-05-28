# Realiza los escaneos de DHCP
# Israel Torres Gonzalo
# TFG UOC 2020/2021 S2

from shlex import split
import subprocess
import os
import sqlite3

scriptdir = (os.path.dirname(os.path.realpath(__file__)))


def scan(onlyname, interface):
    # Se crea un fichero log donde se vuelca la salida a consola del comando necesario
    vulnerable = 0
    logfile = open(scriptdir + '/audits/' + onlyname + '.dhcp.log', 'a+')
    commandraw = ('sudo python /opt/DHCPig/pig.py -o ' + interface)
    command = split(commandraw)
    process = subprocess.Popen(command,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)

    # Se revisa el fichero log en búsqueda de las palabras clave para determinar si la red es vulnerable
    while True:
        output = process.stdout.readline()
        logfile.write(output)
        print(output.strip())
        if '[ -- ] [DONE] DHCP pool exhausted!' in output.strip():
            vulnerable = 1
            logfile.close()
            break
        if '[ -- ] [FAIL] No DHCP offers detected - aborting' in output.strip():
            vulnerable = 0
            logfile.close()
            break

    # Se insertan los datos en la base de datos
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    sql_insert = """INSERT INTO dhcp (ip, command, vunl, output) VALUES (?,?,?,?);"""
    if vulnerable == 1:
        registro = ('dhcp server', commandraw, 'SI', scriptdir + '/audits/' + onlyname + '.dhcp.log')
    if vulnerable == 0:
        registro = ('dhcp server', commandraw, 'NO', scriptdir + '/audits/' + onlyname + '.dhcp.log')
    cursor.execute(sql_insert, registro)
    connection.commit()
    connection.close()

    # Devolvemos 1 o 0 dependiendo de si es vulnerable o no
    return vulnerable
