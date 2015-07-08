#!/bin/sh
#
# 'updt-data' is the file data that contains a lot of real update messages
# $1 is a number of messages form file data that you whish to send to the peer
#
perl ./bgp_simple.pl -myas 559 -myip 172.31.1.2 -peerip 172.31.1.1 -peeras 12654 -p updt-data -m $1
