# Lee la configuracion desde archivo INI -> lanaudit.ini
# Israel Torres Gonzalo
# TFG UOC 2020/2021 S2

import configparser

config = configparser.ConfigParser()

try:
    with open('lanaudit.ini') as f:
        config.read_file(f)
except IOError:
    raise SystemExit('Error: Error al acceder o leer el fichero de configuracion <lanaudit.ini>')


def readConfig(myVar):
    return config['NETCONFIG'][myVar]


def manyRanges():
    ranges = 0
    for i in range(1, 9):
        i = str(i)
        if config.has_option('NETCONFIG', 'IPRange' + i):
            ranges = ranges +1
        else:
            break
    ranges = int(ranges)
    return ranges


def readBrute(myVar):
    return config['BRUTEFORCE'][myVar]
