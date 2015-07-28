package net.floodlightcontroller.bgpsec;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class BGPSecPrefixChainParser {
	/**
	 * Parse prefixes in NLRI and Withdrawn routes
	 * @param nlri
	 * @return separated prefixes where in list, first
	 * is in decimal format and the second is the same
	 * prefix, but in hexadecimal
	 */
	static public List<String> prefixParser(String prefix) {
		List<String> data = new ArrayList<String>();
		int countPos = 1;
		int bitsLen;
		String[] dualFormat = new String[2];
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
				dualFormat[0] = "0.0.0.0/0";
				dualFormat[1] = "0000";
				Collections.addAll(data, dualFormat);
				countPos = 2;
			} else
				dualFormat[0] = BGPSecUtils.hexToIPDec(prefix.substring(2,countPos)) + 
						 "/" + String.valueOf(bitsLen);
				dualFormat[1] = prefix.substring(0,2) + prefix.substring(2,countPos);
				Collections.addAll(data, dualFormat);
				prefix = prefix.substring(countPos);
		}
		return data;
	}	

}
