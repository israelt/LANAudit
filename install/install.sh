#!/bin/bash
# EJECUTAR CON PERMISOS DE ROOT / SUDO
# PROBADO EN KALI2020.4 Y KALI2021.1
# ACTUALIZANDO DISTRIBUCION
sudo apt -y update
sudo apt -y upgrade
# INSTALANDO DHCPIG
echo INSTALANDO DHCPIG
cd /opt
sudo wget --trust-server-names -O master.zip https://github.com/secdev/scapy/archive/refs/tags/v2.3.3.zip
sudo unzip -o master.zip
cd scapy-2.3.3
sudo python setup.py install
cd /opt
sudo git clone git://github.com/kamorin/DHCPig
# INSTALANDO NBTSCAN
echo INSTALANDO NBTSCAN
sudo apt install nbtscan-unixwiz
# INSTALANDO IMPACKET
echo INSTALANDO IMPACKET
cd /opt
sudo wget https://github.com/SecureAuthCorp/impacket/releases/download/impacket_0_9_22/impacket-0.9.22.tar.gz
sudo tar -xvf ./impacket-0.9.22.tar.gz
cd impacket-0.9.22
apt -y install python3-pip
pip3 install -r requirements.txt
# INSTALANDO NMAP_SCRIPTS
echo INSTALANDO NMAP_SCRIPTS
cd /opt
sudo git clone git://github.com/psc4re/NSE-scripts
cd NSE-scripts
sudo cp cve-2020-0796.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
# INSTALANDO SMBGHOST
echo INSTALANDO SMBGHOST
cd /opt
sudo git clone git://github.com/ollypwn/SMBGhost
cd SMBGhost
# INSTALANDO ARACHNI
echo INSTALANDO ARACHNI
cd /opt
sudo wget https://github.com/Arachni/arachni/releases/download/v1.5.1/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz
sudo tar -xvf ./arachni-1.5.1-0.5.12-linux-x86_64.tar.gz
sudo chown kali:kali ./arachni-1.5.1-0.5.12 -R
export OPENSSL_CONF=/etc/ssl/
# INSTALANDO ROCKME + MINROCKME
echo INSTALANDO ROCKME Y MINROCKME
cd /usr/share/wordlists
gunzip rockyou.txt.gz
head -n100 rockyou.txt >> minrockyou.txt
# INSTALANDO MODULO DE IMPRESION A PDF
pip3 install weasyprint --no-input
# CONFIGURANDO PERMISOS PARA SCRIPTS DE ARRANQUE Y AUTO-ARRANQUE
sudo chmod +x /opt/lanaudit/lanaudit.sh
sudo chmod +x /opt/lanaudit/install/lanaudit-boot.sh
sudo chmod +x /opt/lanaudit/install/enable_autostart.sh
sudo chmod +x /opt/lanaudit/install/disable_autostart.sh
