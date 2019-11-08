package net.floodlightcontroller.bgpsecx.sessioncontrol;

/* 
 * RFCs 
 * 4271 (A Border Gateway Protocol 4 (BGP-4))
 * 5492 (Capabilities Advertisement with BGP-4)
 * 
 */

import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.bgpsecx.BGPSecMain;
import net.floodlightcontroller.bgpsecx.general.BGPSecDefs;
import net.floodlightcontroller.bgpsecx.general.BGPSecUtils;
import net.floodlightcontroller.bgpsecx.sessioncontrol.BGPSecClientHandle;

public class BGPSecOpenHandle {
	protected static Logger log = LoggerFactory.getLogger(BGPSecOpenHandle.class);
	
	public static StringBuilder MY_DEFAULT_OPEN_HEADER = new StringBuilder()
						.append(BGPSecUtils.decToHexWithPad(BGPSecDefs.OPEN, 2))
						.append(BGPSecUtils.bytesToHex(BGPSecDefs.MY_BGP_VERSION))
						.append(BGPSecUtils.decToHexWithPad(BGPSecDefs.MY_ASN, 4))
						.append(BGPSecUtils.decToHexWithPad(BGPSecDefs.DEFAULT_HOLD_TIME, 4))
						.append(BGPSecDefs.MY_ID);
	public static StringBuilder MY_OPEN_OPTIONAL_PARAM = new StringBuilder()
						.append("1802060104000100010202800002020200020641040000fde9");
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
	public static byte[] checkMessage(byte[] msg){
		int asn = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(msg, 4, 2));
		String id = BGPSecUtils.bytesToHex((BGPSecUtils.subByte(msg, 8, 4)));
		
		/**
		 *  Check whether the peer is authorized to keep a BGP session.
		 *  This also is with compliance RFCXXX for ID equal to zero 
		 *  because id stored in hastable ever will be different of zero.
		 */
		if (!BGPSecMain.containsPeer(asn)){
			log.info("Error: ASN " + asn + " is not a configured peer.");
			return new byte[] {0x01};
		} else if (!BGPSecMain.getAuthPeersValue(asn).equals(id)){
			log.info("Error: ASN " + asn + " is a configured peer, but ID " + BGPSecUtils.ipHexToDec(id) + " not match.");
				return new byte[] {0x01};
		}
		
		// Check the length of message (17 bytes are header mark and the type of message)
		if ((msg.length + 17) < BGPSecDefs.MIN_MSG_LENGTH[BGPSecDefs.OPEN]){
			log.info("Error: message length is wrong.");
			return new byte[] {0x02};
		}

		// Check whether BGP version is compatible	
		if (!Arrays.equals(BGPSecUtils.subByte(msg, 3, 1), BGPSecDefs.MY_BGP_VERSION)){
			log.info("Error: version of BGP isn't compatible.");
			return new byte[] {0x03};
		} 
		
	    // Check min/max Hold Time value
		int holdTime = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(msg, 6, 2));
		if (holdTime < BGPSecDefs.MIN_HOLD_TIME || holdTime > BGPSecDefs.MAX_HOLD_TIME){
			log.debug("Error: the hold time value isn't aceptable.");
			return new byte[] {0x04};
		}

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
		
		if (BGPSecMain.sessionData.containsPeer(id)){
			log.info("Há ID...........");
		} else {
			BGPSecClientHandle.setSessionPar("thread", 0);
			BGPSecClientHandle.setSessionPar("asn", asn);
			BGPSecClientHandle.setSessionPar("session_state", 0);
			BGPSecClientHandle.setSessionPar("next_msg", BGPSecDefs.KEEPALIVE);
			BGPSecClientHandle.setSessionPar("hold_timer", holdTime);
			BGPSecClientHandle.setSessionPar("hold_time", System.currentTimeMillis()/1000);
			BGPSecClientHandle.setSessionPar("msg_timeout", System.currentTimeMillis()/1000);
			BGPSecMain.sessionData.setAllParameters(BGPSecClientHandle.getSessionPar(), BGPSecClientHandle.getClientIpAddr());	
		}
		
		// There are not any errors in OPEN message. Reply with other OPEN + a concatenated KEEPALIVE
		return BGPSecUtils.hexStrToByteArray(buildMsg.toString());
	}
}
