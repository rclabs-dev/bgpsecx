package net.floodlightcontroller.bgpsecx.sessioncontrol;

import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BGPSecSetGetSessionData {
	protected static Logger log = LoggerFactory.getLogger(BGPSecSetGetSessionData.class);

	/**
	 *  sessionData an innerSessionData stores all data for BGP FSM
	 *  The key for external hashmap is the IP address 
	 */
	private HashMap<String, HashMap<String, Object>> sessionData  = 
			       	new HashMap<String, HashMap<String, Object>>();
	
	/**
	 * Clear all data on hastables
	 */
	public void clearAllSessionData(){
		sessionData.clear();	
		log.info("Data for all BGP sessions was cleared.");
	}
	
	public int getSize(){
		return sessionData.size();	
	}
	
	public boolean containsPeer(String id){
		return sessionData.containsKey(id);
	}	
	
	public void setAllParameters(HashMap<String, Object> data, String id){
		sessionData.put(id, data);
	}

	public void replaceAllParameters(HashMap<String, Object> data, String id){
		sessionData.replace(id, data);
	}
	
	public boolean setOneParameter(String id, String parameter, Object value){
		HashMap<String , Object> data  = new HashMap<String, Object>();
		if (sessionData.containsKey(id)){
			data = sessionData.get(id);
			data.put(parameter, value);
			sessionData.put(id, data);
			return true;
		}
		return false;
	}
	public Object getData(String id, String parameter){
		HashMap<String , Object> data  = new HashMap<String, Object>();
		if (sessionData.containsKey(id)){
			data = sessionData.get(id);
			return data.get(parameter);
		}
		return null;
	}
	
}