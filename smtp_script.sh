#!/bin/bash
{ echo "HELO"; echo "MAIL"; echo "QUIT"; sleep 1; } | sudo telnet $1 $2 > $3
exit