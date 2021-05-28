# Script para configurar la IP del puerto eth
# Israel Torres Gonzalo
# TFG UOC 2020/2021 S2

import os
import time
import socket
import fcntl
import struct
import sqlite3
import os


# Lee la configuration IP de una interfaz para asegurar que tiene una IP asignada
def getLocalIP(interface='eth0'):
    try:
        opensocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            opensocket.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', bytes(interface[:15], 'utf-8'))
        )[20:24])
        opensocket.close()
    except OSError:
        return -1


# Lee la configuration de máscara de red de una interfaz
def getLocalMask(interface='eth0'):
    try:
        return socket.inet_ntoa(fcntl.ioctl(
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
            35099,
            struct.pack('256s', bytes(interface[:15], 'utf-8'))
        )[20:24])
        opensocket.close()
    except OSError:
        return -1


# Configura una interfaz de red por DHCP o por IP Fija
def ipConfig(ip, interface='eth0', mask='255.255.255.0'):
    if ip == 'dynamic':
        cmd = 'ifconfig ' + interface + ' down'
        os.system(cmd)
        time.sleep(1)
        cmd = 'ip addr flush dev ' + interface
        os.system(cmd)
        time.sleep(1)
        cmd = 'dhclient ' + interface
        os.system(cmd)
        time.sleep(2)
        ip = (getLocalIP(interface))
        return ip

    cmd = 'ifconfig ' + interface + ' down'
    os.system(cmd)
    time.sleep(1)
    cmd = 'ifconfig ' + interface + ' ' + ip
    os.system(cmd)
    cmd = 'ifconfig ' + interface + ' netmask ' + mask
    os.system(cmd)
    cmd = 'ifconfig ' + interface + ' up'
    os.system(cmd)
    time.sleep(2)
    ip = (getLocalIP(interface))
    return ip

# Inserta los datos de configuración IP en la base de datos
def saveConfig(onlyname, ip, mask, interface, mode, bruteforce, bonlycheck, buserfile):
    scriptdir = (os.path.dirname(os.path.realpath(__file__)))
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    sql_insert = """INSERT INTO config (ip, mask, interface, mode, bruteforce, bonlycheck, buserfile) VALUES (?,?,?,?,?,?,?);"""
    registro = (ip, mask, interface, mode, bruteforce, bonlycheck, buserfile)
    cursor.execute(sql_insert, registro)
    connection.commit()
    connection.close()
    return 0
