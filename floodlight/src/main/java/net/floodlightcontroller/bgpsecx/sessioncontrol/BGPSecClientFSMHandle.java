package net.floodlightcontroller.bgpsecx.sessioncontrol;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.Temporal;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;

import net.floodlightcontroller.bgpsecx.BGPSecMain;
import net.floodlightcontroller.bgpsecx.general.BGPSecDefs;
import net.floodlightcontroller.bgpsecx.general.BGPSecErrorCodes;
import net.floodlightcontroller.bgpsecx.general.BGPSecUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BGPSecClientFSMHandle extends BGPSecErrorCodes implements Runnable{
	protected static Logger log = LoggerFactory.getLogger(BGPSecClientFSMHandle.class);
    protected Socket cltSocket = null;
    public static Date date = new Date();
    SimpleDateFormat dateFormat = new SimpleDateFormat("dd/M/yyyy hh:mm:ss");
    
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
	private static HashMap<String , Object> sessionParameters  = new HashMap<String, Object>();
	private static String srcIpAddr = null;

    public BGPSecClientFSMHandle(Socket cltSocket) {
        this.cltSocket = cltSocket;
    }

    /* RFC4271, Message header format
     * 0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+          
       |                           Marker                              |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |          Length               |      Type     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       --> Type can be 1=Open; 2=Update; 3=Notification; 4=Keepalive; 5=Route Refresh
     */
    
    public void run() {
    	srcIpAddr = cltSocket.getInetAddress().getHostAddress();
    	DataOutputStream outData = null;
    	int msgType = 0;
    	long timeNow;
    	log.info("Started new TCP session with peer " + srcIpAddr);
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
    							log.info("Min/max BGP message length error.");
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
    					log.info("Unknown BGP message type.");
						outData.write(buildNotificationMsg(new byte[] 
								{NOTIFICATION, HEADER_ERROR, HDR_SUB_BAD_MSG_TYPE}));    
						cltSocket.close();
    				}
    		        
    				
    		        log.info("Received a " + BGPSecDefs.MSG_TYPE[msgType - 1] + 
    		        	      " message from " + srcIpAddr + ", message: " + 
    		        		  BGPSecUtils.bytesToHex(data));
    		        
    		        //log.info("Length of hastable: " + BGPSecIXR.sessionData.getSize());
    		        //log.info("Thread number: " + this.getClass().getName());
    		        
    				switch (msgType) {	
					case BGPSecDefs.OPEN:
						returnData = BGPSecOpenHandle.parseMsg(data);
						// OPEN message ok, reply with local parameters
						if (returnData.length > 3){
							log.info("Reply OPEN message to " + srcIpAddr + 
									  ", message: " + BGPSecUtils.bytesToHex(returnData));
							outData.write(returnData);
						// OPEN message contains one or several wrong parameters,
						// need to send a notification message
						} else{ 
							log.info("OPEN message from " + srcIpAddr + 
									  " not accepted, message: " + BGPSecUtils.bytesToHex(returnData));
						}
						break;
						
					case BGPSecDefs.UPDATE:
						break;
						
					case BGPSecDefs.NOTIFICATION:
						returnData = BGPSecNotificationHandle.checkMessage(data, srcIpAddr);
						//log.info("Reply OPEN message to " + srcIpAddr + 
						//		  ", message: " + BGPSecUtils.bytesToHexString(returnData));
						//outData.write(returnData);	
						break;

					case BGPSecDefs.KEEPALIVE:
						/*log.info("Hashtables Values: " + 
								  sessionParameters.get("asn") + "," +
								  sessionParameters.get("session_state") + "," +
								  sessionParameters.get("thread") + "," +
						          sessionParameters.get("next_msg") + "," +
						          sessionParameters.get("hold_timer") + "," +
						          sessionParameters.get("hold_time") + "," +
						          sessionParameters.get("msg_timeout")); */
			
				        long holdDiff = (System.currentTimeMillis()/1000) - (Long) sessionParameters.get("hold_time");
				        log.info("Hold Time diference: " + holdDiff);		
						timeNow = System.currentTimeMillis();
						if ((Integer)sessionParameters.get("session_state") == 0){
							sessionParameters.put("session_state", 1);
							sessionParameters.put("next_msg", 0);
							sessionParameters.put("hold_time", System.currentTimeMillis()/1000);
							sessionParameters.put("msg_timeout", System.currentTimeMillis()/1000);
							sessionParameters.put("start_session", new Date());
							BGPSecMain.sessionData.replaceAllParameters(sessionParameters, srcIpAddr);
							log.info("BGP Session with peer " + srcIpAddr + " was established!");	
						} else{
							sessionParameters.replace("hold_time", System.currentTimeMillis()/1000);
							sessionParameters.replace("uptime", timeNow);
							BGPSecMain.sessionData.replaceAllParameters(sessionParameters, srcIpAddr);
						}
						log.info("Reply KEEPALIVE Message to " + srcIpAddr + ", uptime: " + 
								BGPSecUtils.getUptime((Date)sessionParameters.get("start_session"), new Date()));
						outData.write(BGPSecUtils.hexStrToByteArray(BGPSecDefs.KEEPALIVE_MSG.toString()));						
						break;
						
					case BGPSecDefs.ROUTE_REFRESH:			
						break;
					}
    			} // while count
    			cltSocket.close();
    		} // while true
    	} catch (IOException e) {
    		log.info("Ended session with peer " + srcIpAddr);
    	}
    }
    
    public byte[] buildNotificationMsg(byte[] codes){
    	byte[] msgToSend = BGPSecUtils.hexStrToByteArray(BGPSecUtils.decToHexWithPad(codes.length + 18, 4));
    	msgToSend = BGPSecUtils.concatBytes(BGPSecDefs.HEADER_MARKER, msgToSend);
    	msgToSend = BGPSecUtils.concatBytes(msgToSend, codes);
    	log.info("NOTIFICATION message reply:  " + BGPSecUtils.bytesToHex(msgToSend));
    	return msgToSend;
    }
    
    public static void setSessionPar(String param, Object value) {
    	sessionParameters.put(param, value);
	}
    
    public static HashMap<String , Object> getSessionPar() {
    	return sessionParameters;
	}
    
    public static String getClientIpAddr() {
    	return srcIpAddr;
	}
}