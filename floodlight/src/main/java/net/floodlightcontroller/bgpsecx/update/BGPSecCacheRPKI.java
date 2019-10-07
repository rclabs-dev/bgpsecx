package net.floodlightcontroller.bgpsecx.update;

import net.floodlightcontroller.bgpsecx.BGPSecX;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BGPSecCacheRPKI {
	protected static Logger log = LoggerFactory.getLogger(BGPSecCacheRPKI.class); 
    private final static int BASE_TIME = 60; // TTL Cache: value in minutes. This should be synchronized with the RPKI 
    private final static long TTL = 1000 * 60 * BASE_TIME; 
	
    /** 
     * Query to the cache, initialize and reinitialize when out of date
     * @param prefix
     * @param asn
     * @param ip
     * @return
     */
	public static boolean getROAOnCache(String prefix, String asn, String ip) {
		long nowTime = System.currentTimeMillis();
		if (BGPSecX.getRPKICacheSize() == 0) { // Cache initialize 
			BGPSecX.setROACache("TTL", String.valueOf(nowTime), "");
			log.info("First query, Cache TTL was initialized: " + BGPSecX.getRPKICacheSize());
			return false;
	    } else { // Verify whether the cache is out of date. If yes, reinitialize.
	    	String[] getTTL = BGPSecX.getRPKICacheValue("TTL");
	    	long timeStamp = nowTime - Long.valueOf(getTTL[0].toString().replaceAll("[\\[\\]]",""));
	    	if (timeStamp > TTL) {
	    		BGPSecX.setRPKICacheClear();
	    		BGPSecX.setROACache("TTL", String.valueOf(nowTime), "");
	    		log.info("Cache TTL was REinitialized."+ BGPSecX.getRPKICacheSize());
	    		return false;
	    	}
	    }			
		// Querying whether ASN/Prefix exist in cache 
		if (BGPSecX.getRPKICacheContains(prefix)){
			String[] values = BGPSecX.getRPKICacheValue(prefix);
			// Verify NLRI routes
			if (ip.equals("") && asn.equals(values[0])) {
				log.info("Quering CACHE for NLRI (" + asn + "/" + prefix + 
						 ")" + ", the result is TRUE.");
				return true;    
			}
			// Verify withdraw routes
			if (asn.equals("") && ip.equals(values[1])) {
				log.info("Quering CACHE for WITHDRAW ROUTES (" + asn + "/" 
			             + prefix + ")" + ", the result is TRUE.");
				return true;   			
			}
		}
		log.info("CACHE returned FALSE.");
	    return false;
	}
	
	/**
	 *  Add new data in the cache
	 * @param prefix
	 * @param asn
	 * @param ip
	 * @return
	 */
	public static boolean setROAOnCache(String prefix, String asn, String ip) {
		BGPSecX.setROACache(prefix, asn, ip);
		return true;
	}
}
