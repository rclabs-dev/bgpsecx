package net.floodlightcontroller.bgpsecx.sessioncontrol;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.bgpsecx.general.BGPSecErrorCodes;
import net.floodlightcontroller.bgpsecx.general.BGPSecUtils;

public class BGPSecNotificationHandle extends BGPSecErrorCodes {
	protected static Logger log = LoggerFactory.getLogger(BGPSecNotificationHandle.class);

	public static byte[] checkMessage(byte[] msg, String peer){
		String notifyData = "";
		int msgLen = msg.length;
		int code = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(msg, 3, 1));
		int subcode = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(msg, 4, 1));
        if (msgLen > 6){
        	notifyData = BGPSecUtils.bytesToHex(BGPSecUtils.subByte(msg, 5));
        }
        
        log.debug("Notification CODE: " + code + ", SUBCODE: " + subcode +
        		  "DATA_ERROR: " + notifyData);
        
        switch (code) {	
		case HEADER_ERROR:
			log.debug("Received a notification for HEADER ERROR, SUBCODE: " + 
					  SUBCODE_HEADER_MSG[subcode - 1] + ", DATA: " + notifyData);
			break;
			
		case OPEN_ERROR:
			log.debug("Received a notification for OPEN ERROR, SUBCODE: " + 
					  SUBCODE_OPEN_MSG[subcode - 1] + ", DATA: " + notifyData);
			break;        

		case UPDATE_ERROR:
			log.debug("Received a notification for UPDATE ERROR, SUBCODE: " + 
					  SUBCODE_OPEN_MSG[subcode - 1] + ", DATA: " + notifyData);
			break;        

		case HOLD_TIMER_EXPIRED:
			log.debug("Received a notification for HOLD TIMER EXPIRED"); 
			break;        

		case FSM_ERROR:
			log.debug("Received a notification for FSM ERROR"); 
			break;        

		case CEASE:
			log.debug("Received a notification for CEASE"); 			
			break;        

        }
		return null;
	}
}