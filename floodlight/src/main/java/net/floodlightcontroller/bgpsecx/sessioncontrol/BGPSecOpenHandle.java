package net.floodlightcontroller.bgpsecx.sessioncontrol;

/* 
 * RFCs 
 * 4271 (A Border Gateway Protocol 4 (BGP-4))
 * 5492 (Capabilities Advertisement with BGP-4)
 * 
 */

import java.util.Arrays;
import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.bgpsecx.BGPSecMain;
import net.floodlightcontroller.bgpsecx.general.BGPSecDefs;
import net.floodlightcontroller.bgpsecx.general.BGPSecUtils;
import net.floodlightcontroller.bgpsecx.sessioncontrol.BGPSecClientFSMHandle;

/* RFC4271, Open message format
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+
|    Version    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     My Autonomous System      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Hold Time           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         BGP Identifier                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Opt Parm Len  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Optional Parameters (variable)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

public class BGPSecOpenHandle {
	protected static Logger log = LoggerFactory.getLogger(BGPSecOpenHandle.class);
	
	public static BGPSecDefs bgpDefs = new BGPSecDefs();
	
	public static StringBuilder MY_DEFAULT_OPEN_HEADER = new StringBuilder()
						.append(BGPSecUtils.decToHexWithPad(BGPSecDefs.OPEN, 2))
						.append(BGPSecUtils.bytesToHex(BGPSecDefs.MY_BGP_VERSION))
						.append(BGPSecUtils.decToHexWithPad(BGPSecDefs.MY_ASN_16, 4))
						.append(BGPSecUtils.decToHexWithPad(BGPSecDefs.DEFAULT_HOLD_TIME, 4))
						.append(BGPSecDefs.MY_ID);
	
	/* RFCs 5492;8126, Optional Parameters format
	 * IANA Capability Code 
	 * https://www.iana.org/assignments/capability-codes/capability-codes.xhtml 
	0                   1
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
	|  Parm. Type   | Parm. Length  |  Parameter Value (variable)
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
	*/
	
	public static StringBuilder MY_OPEN_OPTIONAL_PARAM = new StringBuilder()
						.append("1802060104000100010202800002020200020641040000fde8");
	public static StringBuilder OPEN_MSG_TO_REPLY = new StringBuilder()
						.append(BGPSecDefs.HEADER_MARKER_HEX)
						.append(MY_DEFAULT_OPEN_HEADER)
						.append(MY_OPEN_OPTIONAL_PARAM);
						//.append(BGPSecDefs.KEEPALIVE_MSG);
	
	/*  MSG HEADER (01-04-#ASN-##HT-@@@ID)
	 *  #ASN: AS Number; ##HT: Hold Time; @@ID of speaker
	 *  
	 *  RETURNED CODES
	 *  01: Peer is not authorized to keep a BGP session
	 *  02: The minimum length of message is wrong 
	 *  03: Incompatible BGP Version
	 *  04: Hold Time is out-off the specified
	 */ 
	public static byte[] parseMsg(byte[] msg){
		int rmtPeerAsn = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(msg, 4, 2));
		String rmtPeerId = BGPSecUtils.bytesToHex((BGPSecUtils.subByte(msg, 8, 4)));
		
		/**
		 *  Check whether the peer is authorized to keep a BGP session.
		 */
		//log.info("Total peers: " + Integer.toString(BGPSecMain.getTotalAuthPeers()));
		if (BGPSecMain.containsPeer(rmtPeerAsn)){
			if (BGPSecMain.getAuthPeersId(rmtPeerAsn).equals(rmtPeerId)){
				log.info("OPEN message, error: ASN " + rmtPeerAsn + " is a authorized peer, but ID " + BGPSecUtils.ipHexToDec(rmtPeerId) + " not match.");
				return new byte[] {0x01};
			} else {
				log.info("OPEN message: ASN " + rmtPeerAsn + " from ID " + BGPSecUtils.ipHexToDec(rmtPeerId) + " is a authorized peer.");
			}
		} else {
			log.info("OPEN message, error: ASN " + rmtPeerAsn + " is not a authorized peer.");
			return new byte[] {0x01};
		}
		
		// Check the length of message (17 bytes are header mark and the type of message)
		if ((msg.length + 17) < BGPSecDefs.MIN_MSG_LENGTH[BGPSecDefs.OPEN]){
			log.info("OPEN message, error: message length is wrong.");
			return new byte[] {0x02};
		}

		// Check whether BGP version is compatible	
		if (!Arrays.equals(BGPSecUtils.subByte(msg, 3, 1), BGPSecDefs.MY_BGP_VERSION)){
			log.info("OPEN message, error: version of BGP isn't compatible.");
			return new byte[] {0x03};
		} 
		
	    // Check min/max Hold Time value
		int holdTime = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(msg, 6, 2));
		if (holdTime < BGPSecDefs.MIN_HOLD_TIME || holdTime > BGPSecDefs.MAX_HOLD_TIME){
			log.debug("OPEN message, error: the hold time value isn't aceptable.");
			return new byte[] {0x04};
		}

		int optParamLen = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(msg, 12, 1));
		byte[] optParam =  BGPSecUtils.subByte(msg, 13);
		log.info("OPEN message info: Optional Parameters (Capabilities) Lenght: " + optParamLen + ", content: " + BGPSecUtils.bytesToHex(optParam));
		parseCapabilities(optParamLen, optParam, rmtPeerAsn);
		
		/*
		 * Calculates the total message length (18 is value 
		 * of header mark + 2 bytes of length byte)
		 */
		String msgLen = BGPSecUtils.decToHexWithPad(((MY_DEFAULT_OPEN_HEADER.length() 
						+ MY_OPEN_OPTIONAL_PARAM.length()) / 2) + 18,4);
		StringBuilder buildMsg = new StringBuilder()
						.append(BGPSecDefs.HEADER_MARKER_HEX)
						.append(msgLen)
						.append(MY_DEFAULT_OPEN_HEADER)
						.append(MY_OPEN_OPTIONAL_PARAM)
						.append(BGPSecDefs.KEEPALIVE_MSG);
		
		if (BGPSecMain.sessionData.containsPeer(rmtPeerId)){
			log.info("Há ID...........");
		} else {
			BGPSecClientFSMHandle.setSessionPar("thread", 0);
			BGPSecClientFSMHandle.setSessionPar("asn", rmtPeerAsn);
			BGPSecClientFSMHandle.setSessionPar("session_state", 0);
			BGPSecClientFSMHandle.setSessionPar("next_msg", BGPSecDefs.KEEPALIVE);
			BGPSecClientFSMHandle.setSessionPar("hold_timer", holdTime);
			BGPSecClientFSMHandle.setSessionPar("hold_time", System.currentTimeMillis()/1000);
			BGPSecClientFSMHandle.setSessionPar("msg_timeout", System.currentTimeMillis()/1000);
			BGPSecMain.sessionData.setAllParameters(BGPSecClientFSMHandle.getSessionPar(), BGPSecClientFSMHandle.getClientIpAddr());	
		}
		
		// There are not any errors in OPEN message. Reply with other OPEN + a concatenated KEEPALIVE
		return BGPSecUtils.hexStrToByteArray(buildMsg.toString());
	}

	@SuppressWarnings("static-access")
	public static void parseCapabilities(int optParamLen, byte[] optParam, int peer) {
		int count = 1;
		int newCap;
		String capValue = null;
		while (count < optParamLen) {
			int parLen = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(optParam, count, 1));
			count++;
			newCap = count;
			while (count < (newCap + parLen)) {
				int capType = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(optParam, count, 1));
				count++;
				int capLen = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(optParam, count, 1));
				count++;
				//System.out.println("count: " + count + ", parLen: " + parLen + ", capType: " + capType +", capLen: " + capLen);
				if (capLen != 0) {
					capValue = BGPSecUtils.bytesToHex(BGPSecUtils.subByte(optParam, count, capLen));
				} 
				if (bgpDefs.optCapCodes.containsKey(capType)) {
					log.info("New CAPABILITY type for peer " + peer + " is: " + bgpDefs.optCapCodes.get(capType) + ", and value is: " + capValue);
				}
				count += capLen + 1;
			}
		}
							
	}
}
