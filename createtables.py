# Crea las tablas principales tras el escaneo inicial
# Israel Torres Gonzalo
# TFG UOC 2020/2021 S2

import sqlite3


def maintables(dbname):
    # Se crean las tablas de datos necesarias para los distintos escáneres y procesos
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS ipsearch(" +
                   "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                   "ip varchar(15)," +
                   "mac varchar(17)" +
                   ")")
    connection.commit()
    cursor.execute("CREATE TABLE IF NOT EXISTS config(" +
                   "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                   "ip varchar(15)," +
                   "mask varchar(15)," +
                   "interface varchar(12)," +
                   "mode varchar(4)," +
                   "bruteforce varchar(2)," +
                   "bonlycheck varchar(2)," +
                   "buserfile varchar(255)" +
                   ")")
    connection.commit()
    cursor.execute("CREATE TABLE IF NOT EXISTS nmap(" +
                   "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                   "ip varchar(15)," +
                   "os varchar(100)," +
                   "protocol varchar(5)," +
                   "port int(5)," +
                   "service varchar(20)," +
                   "version varchar(255)" +
                   ")")
    connection.commit()
    cursor.execute("CREATE TABLE IF NOT EXISTS dhcp(" +
                   "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                   "ip varchar(15)," +
                   "command varchar(15)," +
                   "vunl varchar(5)," +
                   "output int(255)" +
                   ")")
    connection.commit()
    cursor.execute("CREATE TABLE IF NOT EXISTS netbios(" +
                   "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                   "ip varchar(15)," +
                   "command varchar(15)," +
                   "vunl varchar(5)," +
                   "output int(255)" +
                   ")")
    connection.commit()
    cursor.execute("CREATE TABLE IF NOT EXISTS rpc(" +
                   "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                   "ip varchar(15)," +
                   "command varchar(15)," +
                   "vunl varchar(5)," +
                   "output int(255)" +
                   ")")
    connection.commit()
    cursor.execute("CREATE TABLE IF NOT EXISTS smb(" +
                   "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                   "ip varchar(15)," +
                   "command varchar(15)," +
                   "vunl varchar(5)," +
                   "output int(255)" +
                   ")")
    connection.commit()
    cursor.execute("CREATE TABLE IF NOT EXISTS smbghost(" +
                   "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                   "ip varchar(15)," +
                   "command varchar(15)," +
                   "vunl varchar(5)," +
                   "output int(255)" +
                   ")")
    connection.commit()
    cursor.execute("CREATE TABLE IF NOT EXISTS snmp(" +
                   "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                   "ip varchar(15)," +
                   "command varchar(15)," +
                   "vunl varchar(5)," +
                   "output int(255)" +
                   ")")
    connection.commit()
    cursor.execute("CREATE TABLE IF NOT EXISTS web(" +
                   "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                   "ip varchar(15)," +
                   "command varchar(15)," +
                   "vunl varchar(5)," +
                   "output int(255)" +
                   ")")
    connection.commit()
    cursor.execute("CREATE TABLE IF NOT EXISTS smtp(" +
                   "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                   "ip varchar(15)," +
                   "command varchar(15)," +
                   "vunl varchar(5)," +
                   "output int(255)" +
                   ")")
    connection.commit()
    cursor.execute("CREATE TABLE IF NOT EXISTS guest(" +
                   "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                   "ip varchar(15)," +
                   "command varchar(15)," +
                   "vunl varchar(5)," +
                   "output int(255)" +
                   ")")
    connection.commit()
    cursor.execute("CREATE TABLE IF NOT EXISTS brute(" +
                   "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                   "ip varchar(15)," +
                   "command varchar(15)," +
                   "vunl varchar(5)," +
                   "output int(255)" +
                   ")")
    connection.commit()
    connection.close()

    return 0
