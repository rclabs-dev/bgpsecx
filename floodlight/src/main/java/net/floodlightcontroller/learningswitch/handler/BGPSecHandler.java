package net.floodlightcontroller.learningswitch.handler;

import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.TransportPort;
import org.slf4j.Logger;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;

public class BGPSecHandler {

	protected static Logger logger;
	
	public boolean checkBGP(Ethernet packet) {
        	// Get IPv4 payload
            IPv4 ipv4 = (IPv4) packet.getPayload();
            // Get src/dst IP address in IPv4
            //byte[] ipOptions = ipv4.getOptions();
            //IPv4Address srcIP = ipv4.getSourceAddress();
            //IPv4Address dstIP = ipv4.getDestinationAddress();

            if (ipv4.getProtocol().equals(IpProtocol.TCP)) {
                // Get TCP payload
                TCP tcp = (TCP) ipv4.getPayload();
                TransportPort srcPort = tcp.getSourcePort();
                TransportPort dstPort = tcp.getDestinationPort();
                if ((srcPort.toString().equals("179")) | (dstPort.toString().equals("179"))) {
                    IPv4Address srcIP = ipv4.getSourceAddress();
                    IPv4Address dstIP = ipv4.getDestinationAddress();
                	System.out.println("Received BGP packet: Source: " + 
                						srcIP + "/" + srcPort + 
                			            ", Dst: " + dstIP + "/" + dstPort);
                	return false;
                } else {
                    System.out.println("Packet is TCP, but isn't BGP");	                		                     	
                	return true;
                }
            }
        System.out.println("Packet isn't TCP");	                		     		
	    return true;
	}
}
