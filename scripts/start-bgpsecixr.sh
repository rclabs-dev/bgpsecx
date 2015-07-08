#!/bin/bash
#
clear
if [ "$EUID" != "0" ]; then
  echo -e "You must be root to run this script.\n"
  exit 1
fi

PROTOCOLS="OpenFlow10,OpenFlow13"
LXCDIR=/var/lib/lxc
CONTROLLER_IP="10.0.3.1"
CONTROLLER_PORT=6653
RPKI_PORT=8081
LOCAL_DIR=$('pwd')
export PATH=$PATH:/usr/local/bin:/usr/local/sbin

# Waiting deamon to start
wait_port_listen() {
    port=$1
    while ! `nc -z localhost $port` ; do
        echo -n .
        sleep 1
    done
}

echo_bold() {
    echo -e "\033[1m${1}\033[0m"
}

# Stop switches and  LXC containers
function reset {
    echo_bold "Stopping and resetting LXC containers/Switches"
    ovs-vsctl del-br sw1
    ovs-vsctl emer-reset
    echo_bold "Stopping LXC containers...";
    for vm in "bgpA" "bgpB" "bgpC" 
    do
    	lxc-stop -n $vm
        while true
        do
            if lxc-info -q -n "$vm" | grep -q "STOPPED"; then
                break;
            fi
            echo -n .
            sleep 1
        done
    done
    sleep 2 

    rm -rf $LXCDIR/bgpA/rootfs/var/run/network/ifstate
    rm -rf $LXCDIR/bgpB/rootfs/var/run/network/ifstate
    rm -rf $LXCDIR/bgpC/rootfs/var/run/network/ifstate

    ifconfig br-bgp down
    brctl delbr br-bgp
}

echo_bold "Starting RPKI Validator, waiting to start..."
#if nc -z localhost $RPKI_PORT; then
#   echo "RPKI Validator started!"
#else
#   $LOCAL_DIR/rpki-validator-app-2.20/rpki-validator.sh start
#   wait_port_listen $RPKI_PORT
#fi

echo_bold "Waiting the FL Controller to start..."
#screen -dmS bgpsecixr
#if nc -z localhost $CONTROLLER_PORT; then
#   echo "Controller started!"
#else
#   cd ../floodlight 
#   screen -S bgpsecixr -p 0 -X stuff "java -jar target/floodlight.jar$(printf \\r)"
#   java -jar target/floodlight.jar
#   wait_port_listen $CONTROLLER_PORT
#fi

echo_bold "Starting the BGP Speakers..."
lxc-start -n bgpA -d
lxc-start -n bgpB -d
lxc-start -n bgpC -d
sleep 2

echo_bold "Creating and configuring the switches..."
ovs-vsctl add-br sw1
ovs-vsctl set Bridge sw1 other-config:datapath-id=0000000000001111
ovs-vsctl set Bridge sw1 protocols=$PROTOCOLS
ovs-vsctl set-controller sw1 tcp:$CONTROLLER_IP:$CONTROLLER_PORT
sleep 2
#
# Add port in switch and bind each port witch BGP speakers (LXC Containers)
#
ovs-vsctl add-port sw1 bgpA.0
ovs-vsctl add-port sw1 bgpB.0
#
# Add bridge without Openflow
#
brctl addbr br-bgp 
brctl addif br-bgp bgpB.1
brctl addif br-bgp bgpC.0
ifconfig br-bgp up
#
read -p "Press. ENTER to STOP network: " nothing
#
trap reset EXIT 
exit 0
