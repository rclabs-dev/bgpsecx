package net.floodlightcontroller.bgpsecx.sessioncontrol;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.Arrays;
import java.util.HashMap;

import net.floodlightcontroller.bgpsecx.BGPSecX;
import net.floodlightcontroller.bgpsecx.general.BGPSecDefs;
import net.floodlightcontroller.bgpsecx.general.BGPSecErrorCodes;
import net.floodlightcontroller.bgpsecx.general.BGPSecUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BGPSecClientHandle extends BGPSecErrorCodes implements Runnable{
	protected static Logger log = LoggerFactory.getLogger(BGPSecClientHandle.class);
    protected Socket cltSocket = null;
    
	/*
	 * Session data parameters
	 * -----------------------
	 * 
	 * asn (int): peer AS number
	 * session_state (int): 0 is waiting OPEN confirmation from remote peer; 
	 *                      1 is when the session was established with remote peer                    
	 * next_msg (int).....: next message to hope from the peer
	 * hold_timer (int)...: negotiated timer for a keepalive
	 * hold_time (long)...: offset time of the last keepalive from remote peer
	 * msg_timeout (long).: timeout for waiting by one message response
	 *   
	 */
	private HashMap<String , Object> sessionParameters  = new HashMap<String, Object>();
	String srcIPAddr = null;

    public BGPSecClientHandle(Socket cltSocket) {
        this.cltSocket = cltSocket;
    }

    public void run() {
    	srcIPAddr = cltSocket.getInetAddress().getHostAddress();
    	DataOutputStream outData = null;
    	int msgType = 0;
    	log.info("Started new session with peer " + srcIPAddr);
    	try {
    		outData = new DataOutputStream(cltSocket.getOutputStream());
    		int count;
        	byte[] buffer = new byte[BGPSecDefs.MAX_LENGTH_MSG];
        	byte[] returnData;
    		while(true) {
    			while ((count = cltSocket.getInputStream().read(buffer, 0, buffer.length)) > 0){
    				byte[] data = new byte[count];
    				data = BGPSecUtils.subByte(buffer, 0, count);
    				// Message with length > 18 avoid runtime error in the next IF 
    				// condition and indirectly already check the minimum message length 
    				if (count > 18) { 
    					if (Arrays.equals(BGPSecUtils.subByte(data, 0, 16), BGPSecDefs.HEADER_MARKER)) {
    						msgType = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(data, 18, 1));
    						int msgLen = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(data, 16, 2));
    						if (count >= BGPSecDefs.MIN_MSG_LENGTH[msgType - 1] && count >= msgLen){
    							// Remove header marker
    							data = BGPSecUtils.subByte(data, 16, count - 16);
    						} else {
    							// Need to make a notification for HEADER_ERROR with SUBCODE 2
    							// and broken the connection with remote peer.
    							log.debug("Min/max BGP message length error.");
    							outData.write(buildNotificationMsg(new byte[] 
    									{NOTIFICATION, HEADER_ERROR, HDR_SUB_BAD_MSG_LEN}));
    							cltSocket.close();
    						}
    					}
    				} 
    				
    				// msgType is equal to 0 if msg don't have a header marker
    				// or msg length is lower than 19 (is not a BGP message)
    				if (msgType == 0) {
    					// Need to make a notification for HEADER_ERROR with SUBCODE 3
    					// and broken the connection with remote peer.
    					log.debug("Unknown BGP message type.");
						outData.write(buildNotificationMsg(new byte[] 
								{NOTIFICATION, HEADER_ERROR, HDR_SUB_BAD_MSG_TYPE}));    
						cltSocket.close();
    				}
    		        
    				
    		        log.debug("Received a " + BGPSecDefs.MSG_TYPE[msgType - 1] + 
    		        	      " message from " + srcIPAddr + ", message: " + 
    		        		  BGPSecUtils.bytesToHexString(data));
    		        
    		        //log.debug("Length of hastable: " + BGPSecIXR.sessionData.getSize());
    		        //log.debug("Thread number: " + this.getClass().getName());
    		        
    				switch (msgType) {	
					case BGPSecDefs.OPEN:
						returnData = openMsgHandle(data);
						// OPEN message ok, reply with local parameters
						if (returnData.length > 3){
							log.debug("Reply OPEN message to " + srcIPAddr + 
									  ", message: " + BGPSecUtils.bytesToHexString(returnData));
							outData.write(returnData);
						// OPEN message contains one or several wrong parameters,
						// need to send a notification message
						} else{ 
							
						}
						break;
						
					case BGPSecDefs.UPDATE:
						break;
						
					case BGPSecDefs.NOTIFICATION:
						returnData = BGPSecNotificationHandle.checkMessage(data, srcIPAddr);
						//log.debug("Reply OPEN message to " + srcIPAddr + 
						//		  ", message: " + BGPSecUtils.bytesToHexString(returnData));
						//outData.write(returnData);	
						break;

					case BGPSecDefs.KEEPALIVE:
						/*log.debug("Hashtables Values: " + 
								  sessionParameters.get("asn") + "," +
								  sessionParameters.get("session_state") + "," +
								  sessionParameters.get("thread") + "," +
						          sessionParameters.get("next_msg") + "," +
						          sessionParameters.get("hold_timer") + "," +
						          sessionParameters.get("hold_time") + "," +
						          sessionParameters.get("msg_timeout")); */
			
				        long a = (System.currentTimeMillis()/1000) - (Long) sessionParameters.get("hold_time");
				        log.debug("Hold Time diference: " + a);		
						
						if ((Integer)sessionParameters.get("session_state") == 0){
							sessionParameters.replace("session_state", 1);
							sessionParameters.replace("next_msg", 0);
							sessionParameters.replace("hold_time", System.currentTimeMillis()/1000);
							sessionParameters.replace("msg_timeout", System.currentTimeMillis()/1000);
							BGPSecX.sessionData.replaceAllParameters(sessionParameters, srcIPAddr);
							log.info("BGP Session with peer " + srcIPAddr + " was established!");	
						} else{
							sessionParameters.replace("hold_time", System.currentTimeMillis()/1000);
							BGPSecX.sessionData.replaceAllParameters(sessionParameters, srcIPAddr);
						}
						
						log.debug("Reply KEEPALIVE Message to " + srcIPAddr);
						outData.write(BGPSecUtils.hexStrToByteArray(BGPSecDefs.KEEPALIVE_MSG.toString()));						
						break;
						
					case BGPSecDefs.ROUTE_REFRESH:			
						break;
					}
    			} // while count
    			cltSocket.close();
    		} // while true
    	} catch (IOException e) {
    		log.info("Ended session with peer " + srcIPAddr);
    	}
    }
    
    public byte[] openMsgHandle(byte[] msg){	
		/*  MSG HEADER (01-04-#ASN-##HT-@@@ID)
		*  #ASN: AS Number; ##HT: Hold Time; @@ID of speaker
		*  
		*  RETURNED CODES
		*  01: Peer is not authorized to keep a BGP session
		*  02: The minimum length of message is wrong 
		*  03: Incompatible BGP Version
		*  04: Hold Time is out-off the specified
		*/ 
		int asn = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(msg, 4, 2));
		String id = BGPSecUtils.bytesToHexString((BGPSecUtils.subByte(msg, 8, 4)));
		
		/**
		*  Check whether the peer is authorized to keep a BGP session.
		*  This also is with compliance RFCXXX for ID equal to zero 
		*  because id stored in hastable ever will be different of zero.
		*/
		if (!BGPSecX.containsPeer(asn))
			return new byte[] {0x01};
		else if (!BGPSecX.getAuthPeersValue(asn).equals(id))
			return new byte[] {0x01};
			
		// Check the length of message (17 are of the header mark and type message)
		if ((msg.length + 17) < BGPSecDefs.MIN_MSG_LENGTH[BGPSecDefs.OPEN]){
			return new byte[] {0x02};
		}
			
		// Check whether BGP version is compatible	
		if (!Arrays.equals(BGPSecUtils.subByte(msg, 3, 1), BGPSecDefs.MY_BGP_VERSION)){
			return new byte[] {0x03};
		} 
			
		// Check min/max Hold Time value
		int holdTime = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(msg, 6, 2));
		if (holdTime < BGPSecDefs.MIN_HOLD_TIME || holdTime > BGPSecDefs.MAX_HOLD_TIME){
			return new byte[] {0x04};
		}
			
		/*
	  	 * Calculates the total message length (18 is value 
		 * of header mark + 2 bytes of length byte)
		 */
		String msgLen = BGPSecUtils.decToHexWithPad(((BGPSecDefs.MY_DEFAULT_OPEN_HEADER.length() 
						+ BGPSecDefs.MY_OPEN_OPTIONAL_PARAM.length()) / 2) + 18,4);
		StringBuilder buildMsg = new StringBuilder()
								.append(BGPSecDefs.HEADER_MARKER_HEX)
								.append(msgLen)
								.append(BGPSecDefs.MY_DEFAULT_OPEN_HEADER)
								.append(BGPSecDefs.MY_OPEN_OPTIONAL_PARAM)
								.append(BGPSecDefs.KEEPALIVE_MSG);
			
		if (BGPSecX.sessionData.containsPeer(id)){
			log.debug("Há ID...........");
		} else {
			sessionParameters.put("thread", 0);
			sessionParameters.put("asn", asn);
			sessionParameters.put("session_state", 0);
			sessionParameters.put("next_msg", BGPSecDefs.KEEPALIVE);
			sessionParameters.put("hold_timer", holdTime);
			sessionParameters.put("hold_time", System.currentTimeMillis()/1000);
			sessionParameters.put("msg_timeout", System.currentTimeMillis()/1000);
			BGPSecX.sessionData.setAllParameters(sessionParameters, srcIPAddr);	
		}
		// There are not any errors in OPEN message. Reply with other OPEN + a concatenated KEEPALIVE
		return BGPSecUtils.hexStrToByteArray(buildMsg.toString());
    }

    public byte[] buildNotificationMsg(byte[] codes){
    	byte[] msgToSend = BGPSecUtils.hexStrToByteArray(BGPSecUtils.decToHexWithPad(codes.length + 18, 4));
    	msgToSend = BGPSecUtils.concatBytes(BGPSecDefs.HEADER_MARKER, msgToSend);
    	msgToSend = BGPSecUtils.concatBytes(msgToSend, codes);
    	log.debug("NOTIFICATION message reply:  " + BGPSecUtils.bytesToHexString(msgToSend));
    	return msgToSend;
    }
}