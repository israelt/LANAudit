#! /bin/sh
# /etc/init.d/lanaudit-boot.sh
### BEGIN INIT INFO
# Provides:          lanaudit.sh
# Required-Start:    $all
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:
# Short-Description: Start lanaudit at boot time
# Description:       Run lan audit
### END INIT INFO
cd /opt/lanaudit
sudo python3 /opt/lanaudit/main.py
