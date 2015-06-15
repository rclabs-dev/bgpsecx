package net.floodlightcontroller.bgpsec;

import java.util.ArrayList;

public class BGPSecPrefixParser {
	/**
	 * Parse prefixes in NLRI and Withdrawn routes
	 * @param nlri
	 * @return
	 */
	static public ArrayList<String> prefixParser(String prefix) {
		ArrayList<String> data = new ArrayList<String>();
		int countPos = 1;
		int bitsLen;
		while (! prefix.equals("")) {
			bitsLen = BGPSecUtils.hexToDec(prefix.substring(0,2));
			if (bitsLen <= 8 )
				countPos = 4;
			else
				if (bitsLen > 8 && bitsLen < 17 )
				countPos = 6;
			else
				countPos = 8;
			
			if (bitsLen == 0) {
				data.add("0.0.0.0/0");
				countPos = 2;
			} else
				data.add(BGPSecUtils.hexToIPDec(prefix.substring(2,countPos)) + 
							 "/" + String.valueOf(bitsLen));
				prefix = prefix.substring(countPos);
		}
		return data;
	}	

}
