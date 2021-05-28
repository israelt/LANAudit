# Realiza los escaneos de fuerza bruta
# Israel Torres Gonzalo
# TFG UOC 2020/2021 S2

from shlex import split
import subprocess
import os
import sqlite3

scriptdir = (os.path.dirname(os.path.realpath(__file__)))


def scan(onlyname, ip, port, userfile, onlycheck='1'):
    # Se define el servicio por el número de puerto abierto a escanear
    service = 'unknow'
    if port == '21': service = 'ftp://'
    if port == '22': service = 'ssh://'
    if port == '23': service = 'telnet://'
    if port == '389': service = 'ldap2://'
    if port == '445': service = 'smb://'
    if port == '3306': service = 'mysql://'
    if port == '5900': service = 'rdp://'
    if service == 'unknow': return 2

    # Se define el fichero de contraseñas dependiendo de si es el modo prueba o el modo real
    if onlycheck == '0': passfile = '/usr/share/wordlists/rockyou.txt'
    if onlycheck == '1': passfile = '/usr/share/wordlists/minrockyou.txt'

    # Se definen los parámetros y variables iniciales y se abren los ficheros de log y errores necesarios
    logfile = open(scriptdir + '/audits/' + onlyname + '.bruteforce_' + ip + '_port' + port + '.log', 'w+')
    errorfile = open(scriptdir + '/audits/' + onlyname + '.bruteforce_' + ip + '_port' + port + '.error.log', 'w+')

    # Comienza el escaneo mediante comando con volcado a los ficheros anteriormente definidos
    commandraw = ('hydra -L ' + userfile + ' -P ' + passfile + ' ' + service + ip)
    command = commandraw.split()
    subprocess.call(command, stdout=logfile, stderr=errorfile)
    logfile.close()
    errorfile.close()

    # Se insertan los datos en la BBDD
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    sql_insert = """INSERT INTO brute (ip, command, vunl, output) VALUES (?,?,?,?);"""
    registro = (ip, commandraw, port, scriptdir + '/audits/' + onlyname + '.bruteforce_' + ip + '.log')
    cursor.execute(sql_insert, registro)
    connection.commit()
    connection.close()

    return 0
