#!/bin/bash
# EJECUTAR CON PERMISOS DE ROOT / SUDO EN UNA DISTRIBUCION RECIEN INSTALADA
# PROBADO EN KALI2020.4 Y KALI2021.1
# INSTALANDO AUTOARRANQUE
echo [Unit] > /etc/systemd/system/rc-local.service
echo  Description=/etc/rc.local Compatibility >> /etc/systemd/system/rc-local.service
echo  ConditionPathExists=/etc/rc.local >> /etc/systemd/system/rc-local.service
echo                                    >> /etc/systemd/system/rc-local.service
echo [Service]  >> /etc/systemd/system/rc-local.service
echo  Type=forking  >> /etc/systemd/system/rc-local.service
echo  ExecStart=/etc/rc.local start  >> /etc/systemd/system/rc-local.service
echo  TimeoutSec=0  >> /etc/systemd/system/rc-local.service
echo  StandardOutput=tty  >> /etc/systemd/system/rc-local.service
echo  RemainAfterExit=yes  >> /etc/systemd/system/rc-local.service
echo  SysVStartPriority=99  >> /etc/systemd/system/rc-local.service
echo                                    >> /etc/systemd/system/rc-local.service
echo [Install] >> /etc/systemd/system/rc-local.service
echo  WantedBy=multi-user.target >> /etc/systemd/system/rc-local.service

rm /etc/rc.local -rf
printf '%s\n' '#!/bin/bash' 'sh /opt/lanaudit/lanaudit.sh' 'exit 0' | sudo tee -a /etc/rc.local

sudo chmod +x /etc/rc.local

sudo systemctl enable rc-local

sudo systemctl start rc-local.service &
