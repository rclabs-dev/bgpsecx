package net.floodlightcontroller.bgpsec;

import java.util.Hashtable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BGPSecUpdateParser extends BGPSecDefs{
	protected static Logger log = LoggerFactory.getLogger(BGPSecUpdateParser.class);

	public static Hashtable<Integer, byte[]> msgParser (byte[] updateMsg) {
		/* attrData keys contain:
		 * 0: Total message length
		 * 1: Withdrawn routes
		 * 2: ORIGIN type
		 * 3: AS_PATH segment type
		 * 4: First ASN in AS_PATH
		 * 5: Last ASN in AS_PATH
		 * 6: Chain of the ASNs in AS_PATH
		 * 7: NEXT_HOP
		 * 8: NLRI
		 */
		Hashtable<Integer, byte[]> dataParsed = new Hashtable<Integer, byte[]>();
		int decTmp, attrType, attrLen, totalASN;
		byte[] byteTmp, attrValue;
		// It store total path attribute lenght
		int totalAttr;
		int countPos = 0;
		int stepPos;
		
		/* TOTAL LENGHT MESSAGE
		 * Contain the total length of the message in bytes, including the fields of the header
		 */
		dataParsed.put(0, BGPSecUtils.subByte(updateMsg, 0, 2));
		
		
		/*
		 * WITHDRAWN ROUTES LENGHT
		 * This 2-octets unsigned integer indicates the total length of
         * the Withdrawn Routes field in octets. A value of 0 indicates 
         * that no routes are being withdrawn from service, and that the 
         * withdrawn routes field is not present in this UPDATE message.
         * 
         * WITHDRAWN ROUTES
         * Is a variable-length field that contains a list of IP
         * address prefixes for the routes that are being withdrawn from
         * service.  Each IP address prefix is encoded as a 2-tuple of the
         * form <length, prefix>. The Length field indicates the length 
         * in bits of the IP address prefix. A length of zero indicates 
         * a prefix that matches all IP addresses (with prefix, itself, 
         * of zero octets). The Prefix field contains an IP address prefix, 
         * followed by the minimum number of trailing bits needed to make 
         * the end of the field fall on an octet boundary.  Note that the 
         * value of trailing bits is irrelevant.
         */
		decTmp = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(updateMsg, 3, 2));
		if (decTmp != 0) { // There are unfeasible routes
			// Contains total list of withdrawn routes
			dataParsed.put(1, BGPSecUtils.subByte(updateMsg, 5, decTmp));
			// Cut the msg until Total Path Attribute
			updateMsg = BGPSecUtils.subByte(updateMsg, 5 + decTmp);
			log.info("Message contains withdrawn/unfeasible Routes");
		} else {
			// Cut until Total Path Attribute
			updateMsg = BGPSecUtils.subByte(updateMsg,5);
		}	
		
		/* 
		 * PATH ATTRIBUTES
		 * Total Path Attribute Length are 2-octet unsigned integer 
		 * indicates the total length of the Path Attributes field in 
		 * octets. Each path attribute is a triple <attribute type, 
		 * attribute length, attribute value> of variable length.
		 *  
		 * Attribute Type is a two-octet field that consists of the 
		 * Attribute Flags octet, followed by the Attribute Type Code 
		 * octet. The fourth high-order bit (bit 3) of the Attribute 
		 * Flags octet is the Extended Length bit. It defines whether 
		 * the Attribute Length is one octet (if set to 0) or two octets 
		 * (if set to 1). 
		 */
		// Get total path attribute lenght
		totalAttr = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(updateMsg, 0, 2));
		if (totalAttr != 0) {
			log.info("Total Path Attribute Lenght: "  + totalAttr + " bytes");
			// Cut the msg until first Path Attribute
			updateMsg = BGPSecUtils.subByte(updateMsg, 2);
			while (countPos < totalAttr) {
				// Otimizar expressão abaixo
				decTmp = Integer.parseInt(BGPSecUtils.bitFlags(BGPSecUtils.bytesToHexString(BGPSecUtils.subByte(updateMsg, 0, 1))));
				// Path Attribute length are one or two octects.
				if (decTmp == 0)
					stepPos = 1;  
				else
					stepPos = 2;
			   
				/* Parse ORIGIN Attribute
				 * (type code 1) is a well-known mandatory attribute that defines the
				 * origin of the path information.  The data octet can assume the following 
				 * values: 0 (IGP - NLRI is interior to the originating AS); 1 EGP - NLRI 
				 * learned via the EGP protocol [RFC904]); 2 (INCOMPLETE - NLRI learned by 
				 * some other means
				 */
				
				attrType = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(updateMsg, 1, 1));
				attrLen = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(updateMsg, 2, stepPos));
				attrValue = BGPSecUtils.subByte(updateMsg, 2 + stepPos, attrLen);		
				
				if (attrType == ORIGIN) {
					dataParsed.put(2,attrValue);
					log.info("In ORIGIN attribute, the type is: " + BGPSecUtils.bytesToInt(attrValue) + 
							 " (" + ORIGIN_VALUE[ BGPSecUtils.bytesToInt(attrValue)] + ")");
					// Cut the msg to the next one path attribute
					
				/* Parse AS_PATH attribute
				 * Is a well-known mandatory attribute that is composed of a sequence 
				 * of AS path segments.  Each AS path segment is represented by a 
				 * triple <path segment type, path segment length, path segment value>.
				 * The path segment type is a 1-octet length field with the following 
				 * values defined: 1 (AS_SET: unordered set of ASes a route in the 
				 * UPDATE message has traversed; 2 (AS_SEQUENCE: ordered set of ASes a 
				 * route in the UPDATE message has traversed. The path segment length 
				 * is a 1-octet length field, containing the number of ASes (not the 
				 * number of octets) in the path segment value field. The path segment 
				 * value field contains one or more AS numbers, each encoded as a 
				 * 2-octet length field.
				 */					
				
				} else if (attrType == AS_PATH) {
					byteTmp = BGPSecUtils.subByte(attrValue, 0, 1);
					dataParsed.put(3, byteTmp);
					log.info("In AS_PATH Attribute, the segment Type is: " + 
							SEGMENT_TYPE[BGPSecUtils.bytesToInt(byteTmp) - 1]);
					   
					totalASN = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(attrValue, 1, 1));
					log.info("Total ASN (s) in AS_PATH: " + totalASN);
					// Get first ASN in AS_Path
					decTmp = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(attrValue, 2, 2));
					   
					if (decTmp == 0) { // 0000 precede each ASN
						totalASN = totalASN * 2;
						// Get first ASN in AS_PATH that differs of zero
						dataParsed.put(4, BGPSecUtils.subByte(attrValue, 4, 2));
					}
					   
					for (int i = 1; i <= totalASN; i++) {
						byteTmp = BGPSecUtils.subByte(attrValue, 2 * i, 2);
						log.info("AS Number in AS_PATH: " + BGPSecUtils.bytesToInt(byteTmp));
					}
					// Get last ASN in AS_PATH
					dataParsed.put(5, byteTmp);
					// Get chain of the ASNs in AS_PATH
					dataParsed.put(6, attrValue);   
					   
					/* Parse NEXT_HOP attribute 
					* Is a well-known mandatory attribute that defines the (unicast) IP 
					* address of the router that SHOULD be used as the next hop to the 
					* destinations listed in the NLRI field of the UPDATE message.
					*/
					
					} else if (attrType == NEXT_HOP) {
						dataParsed.put(7, attrValue);
						log.info("Attribute is NEXT_HOP, value of IP Address is: " + BGPSecUtils.byteToIPDec(attrValue));

					// Parse others attributes for only count octets in update message				   
				    } else {
				    	log.info("Attribute Type: " + ATTR_TYPE[attrType - 4] + ", value: " +  
							         BGPSecUtils.bytesToHexString(attrValue));
				    }
				
					updateMsg = BGPSecUtils.subByte(updateMsg, attrLen + stepPos + 2);				
					countPos = countPos + attrLen + stepPos + 2;
					//System.out.println("----> updateMsg: " + BGPSecUtils.bytesToHexString(updateMsg));
					//System.out.println("----> countPos:" + countPos + ", totalAttr: " + totalAttr);
				
				}
			}
		    dataParsed.put(8, updateMsg);
			return dataParsed;	
		}
}
