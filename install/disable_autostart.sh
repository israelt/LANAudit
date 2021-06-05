#!/bin/bash
# EJECUTAR CON PERMISOS DE ROOT / SUDO EN UNA DISTRIBUCION RECIEN INSTALADA
# PROBADO EN KALI2020.4 Y KALI2021.1
# DESINSTALANDO AUTOARRANQUE
sudo update-rc.d lanaudit-boot.sh remove
sudo rm /etc/init.d/lanaudit-boot.sh