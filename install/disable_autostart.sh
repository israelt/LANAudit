#!/bin/bash
# EJECUTAR CON PERMISOS DE ROOT / SUDO EN UNA DISTRIBUCION RECIEN INSTALADA
# PROBADO EN KALI2020.4 Y KALI2021.1
# DESINSTALANDO AUTOARRANQUE
sudo systemctl stop rc-local.service
sudo systemctl disable rc-local
rm /etc/rc.local -rf
rm /etc/systemd/system/rc-local.service -rf
