#!/bin/sh
set -eu
printf '%s\n' 'macOS: no independently validated native security sandbox ships with this build.' \
'Use a disconnected virtual machine or physically disable all network connections.' \
'Application socket guards alone are not containment. Do not execute unknown collectors.'
exit 3
