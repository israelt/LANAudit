# Realiza los escaneos de SMBGHOST a cada host
# Basado en el script SMBGhost de ollypwn (git://github.com/ollypwn/SMBGhost)
# Israel Torres Gonzalo
# TFG UOC 2020/2021 S2

import os
import sqlite3
import socket
import struct

scriptdir = (os.path.dirname(os.path.realpath(__file__)))

# Se define el payload necesario para detectar la vulnerabilidad
pkt = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'


def scan(mainname, ip):

    # Se abre un socket al puerto 445 y se envía el payload
    sock = socket.socket(socket.AF_INET)
    sock.settimeout(5)

    try:
        sock.connect(( str(ip),  445 ))
        sock.send(pkt)
        nb, = struct.unpack(">I", sock.recv(4))
        res = sock.recv(nb)
        # Se determina la vulnerabilidad por el resultado al envío del payload
        if res[68:70] != b"\x11\x03" or res[70:72] != b"\x02\x00":
            vulnerable = 0
        else:
            vulnerable = 1

    # Si no hay respuesta al payload o no hay conexión se considera no vulnerable
    except:
        sock.close()
        vulnerable = 0

    # Se insertan los datos en la base de datos
    dbname = mainname + '.db'
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    sql_insert = """INSERT INTO smbghost (ip, command, vunl, output) VALUES (?,?,?,?);"""
    if vulnerable == 1:
        registro = (ip, 'Socket SMBGHOST TEST', 'SI', '')
    if vulnerable == 0:
        registro = (ip, 'Socket SMBGHOST TEST', 'NO', '')
    cursor.execute(sql_insert, registro)
    connection.commit()
    connection.close()

    # Devolvemos 1 o 0 dependiendo de si es vulnerable o no
    return vulnerable
