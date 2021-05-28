# Realiza los escaneos de servicios WEB a cada host
# Israel Torres Gonzalo
# TFG UOC 2020/2021 S2

import subprocess
import os
import sqlite3

scriptdir = (os.path.dirname(os.path.realpath(__file__)))


def scan(onlyname, ip, port):
    # Se definen los parámetros y variables iniciales y definen los ficheros de logs necesarios
    vulnerable = 0
    logfile = scriptdir + '/audits/' + onlyname + '.web_' + ip + '_port' + port + '.afr'
    reportfile = scriptdir + '/audits/' + onlyname + '.web_' + ip + '_port' + port

    # Comienza el escaneo mediante la invocación de un script sh propio con volcado a los ficheros anteriormente 
    # definidos 
    if port == '443':
        commandraw = ('sudo /opt/arachni-1.5.1-0.5.12/bin/arachni https://' + ip + ' --output-verbose --report-save-path=' + logfile)
    else:
        commandraw = ('sudo /opt/arachni-1.5.1-0.5.12/bin/arachni http://' + ip + ' --output-verbose --report-save-path=' + logfile)
    command = commandraw.split()
    subprocess.call(command)

    command = ('sudo /opt/arachni-1.5.1-0.5.12/bin/arachni_reporter ' + logfile + ' --reporter=html:outfile=' + reportfile + '.html.zip')
    command = command.split()
    subprocess.call(command)

    command = ('sudo /opt/arachni-1.5.1-0.5.12/bin/arachni_reporter ' + logfile + ' --reporter=txt:outfile=' + reportfile + '.txt')
    command = command.split()
    subprocess.call(command)

    # Se insertan los datos en la BBDD
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    sql_insert = """INSERT INTO web (ip, command, vunl, output) VALUES (?,?,?,?);"""
    registro = (ip, commandraw, port, reportfile + '.html.zip')

    cursor.execute(sql_insert, registro)
    connection.commit()
    connection.close()

    return 0
