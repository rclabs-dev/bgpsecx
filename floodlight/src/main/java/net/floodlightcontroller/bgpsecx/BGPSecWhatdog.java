package net.floodlightcontroller.bgpsecx;

import net.floodlightcontroller.bgpsecx.sessioncontrol.BGPSecSetGetSessionData;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BGPSecWhatdog implements Runnable{
	protected static Logger log = LoggerFactory.getLogger(BGPSecWhatdog.class);
	BGPSecSetGetSessionData sessionData = new BGPSecSetGetSessionData();
	
    public void run() {
    	log.info("BGP Whatdog activated.");
    	//while(true){
    		//log.debug("Length of hastable: " + BGPSecIXR.sessionData.getSize());
    		//log.debug("Time: " + System.currentTimeMillis()/1000);
    	//}
 
    }
}