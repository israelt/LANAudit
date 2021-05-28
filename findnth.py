# Script para encontrar la enésima coincidencia en una cadena
# Israel Torres Gonzalo
# TFG UOC 2020/2021 S2

def find_nth(string, substring, n):
    if n == 1:
        return string.find(substring)
    else:
        return string.find(substring, find_nth(string, substring, n - 1) + 1)
