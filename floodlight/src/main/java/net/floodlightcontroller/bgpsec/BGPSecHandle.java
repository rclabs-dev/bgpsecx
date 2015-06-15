package net.floodlightcontroller.bgpsec;

import java.util.Hashtable;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.packet.IPacket;

public class BGPSecHandle extends BGPSecDefs{
	protected static Logger log = LoggerFactory.getLogger(BGPSecHandle.class); 
	/* attrData keys contain:
	 * 0: Total message length
	 * 1: Withdrawn routes
	 * 2: ORIGIN type
	 * 3: AS_PATH segment type
	 * 4: First ASN in AS_PATH
	 * 5: Last ASN in AS_PATH
	 * 6: Chain of the ASNs in AS_PATH
	 * 7: NEXT_HOP
	 * 8: NLRI
	 */
	 static Hashtable<Integer, byte[]> attrData = new Hashtable<Integer, byte[]>();

	public static boolean processBGPPkt(IPacket payload, IPv4Address speakerIP) {
		byte[] bgpMsg = payload.serialize();
		int msg = bgpMsg.length;
		if (!(msg < MIN_LENGTH_MSG || msg > MAX_LENGTH_MSG)){
			// Remove from/ bgp message the initial bytes until unfeasible routes
			bgpMsg = BGPSecUtils.subByte(bgpMsg, 16, msg - 16);
			log.info("BGP message payload: " + BGPSecUtils.bytesToHexString(bgpMsg));
			// Get BGP message type
			msg = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(bgpMsg, 2, 1));
			log.info("BGP Message type: " + MSG_TYPE[msg]);
			switch (msg) {
				case OPEN:
					return true;
				
				case UPDATE:
					// Parse update message
					attrData = BGPSecUpdateParser.msgParser(bgpMsg);
								
					String asNumber = Integer.toString(BGPSecUtils.bytesToInt(attrData.get(5)));
					String prefChain = null;
					int routeType = 0;
					
					// Verify Witdrawn routes on RPKI
					if (attrData.containsKey(2)) {
						prefChain = BGPSecUtils.bytesToHexString(attrData.get(2));
					}
					
					// Verify NLRI routes on RPKI					
					if (attrData.containsKey(8)) {
						prefChain = BGPSecUtils.bytesToHexString(attrData.get(8));
						routeType = 1;
					} 
					
					System.out.println("***** RESULTADO: " + BGPSecQueryRPKI.roaValidator(prefChain, asNumber, speakerIP.toString(), routeType));


					// Debug		
					/*for (int i=0; i < 9; i++) {
						if (attrData.containsKey(i))
						System.out.println("Key: " + i + ", Value: " + BGPSecUtils.bytesToHexString(attrData.get(i)));
						
					}*/			

					return true;

				case NOTIFICATION:
					return true;

				case KEEPALIVE:
					return true;
					
				case ROUTE_REFRESH:
					return true;
					
				default:
					return true;
			}
		}
		return true;
	}
	
}