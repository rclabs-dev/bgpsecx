package net.floodlightcontroller.bgpsecx.general;

import java.util.HashMap;

import org.projectfloodlight.openflow.types.IPv4Address;
//import org.projectfloodlight.openflow.types.MacAddress;

import com.google.common.base.Strings;

public class BGPSecDefs {
	public final static String RPKI_URL = "http://localhost:8081/api/v1/validity/";
	
	public static final IPv4Address CONTROLLER_ADDR = IPv4Address.of("10.251.11.156"); 
	//public static final MacAddress CONTROLLER_MAC = MacAddress.of("06:94:25:95:d6:63");

	public static final String IP_TO_LISTEN = "127.0.0.1";
	public static final int BGP_PORT = 2179;
	public static final int SOCKET_QUEUE = 0;
	public static final byte[] MY_BGP_VERSION = {0x04};
	public static final int MY_ASN_16 = 65000;
	public static final int MY_ASN_32 = 65000;
	public static final String MY_ID = BGPSecUtils.ipDecToHex(IP_TO_LISTEN);
	
	public static final int DEFAULT_HOLD_TIME = 90;
	public static final int ZERO_HOLD_TIME = 0;
	public static final int MIN_HOLD_TIME = 10;
	public static final int MAX_HOLD_TIME = 66536;
	
	// Group that defines the types of BGP Messages
	public static final int OPEN = 1;
	public static final int UPDATE = 2;
	public static final int NOTIFICATION = 3;
	public static final int KEEPALIVE = 4;
	public static final int ROUTE_REFRESH = 5;
	
	// Group that defines the codes of BGP NOTIFICATION messages
	public static final int MSG_HEADER_ERR = 1;
	public static final int OPEN_MSG_ERR = 2;
	public static final int UPDT_MSG_ERR = 3;
	public static final int HLD_TIMER_EXP = 4;
	public static final int FSM_ERR = 5;
	public static final int CEASE = 6;

	public static final int ORIGIN = 1;
	public static final int AS_PATH = 2;
	public static final int NEXT_HOP = 3;
	public static final String[] MSG_TYPE = {"OPEN", "UPDATE", "NOTIFICATION", "KEEPALIVE", "ROUTE-REFRESH" };
	public static final String[] ATTR_TYPE = { "MULT_EXIT_DISC", "LOCAL_PREF", "ATOMIC_AGGREGATE", "AGGREGATE", 
											   "COMMUNITY", "ORIGINATOR_ID", "CLUSTER_LIST" };
	public static final String[] ORIGIN_VALUE = { "IGP", "EGP", "INCOMPLETE" };
	public static final String[] SEGMENT_TYPE = { "AS_SET", "AS_SEQUENCE" };
	public static final String[] NOTIFY_CODE = {"MSG_HEADER_ERR", "OPEN_MSG_ERR", "UPDT_MSG_ERR", 
												 "HLD_TIMER_EXP", "FSM_ERR", "CEASE" };
	public static final String[] SUBCODE_MSG_HDR = {"UNSYNC", "BAD_MSG_LEN", "BAD_MSG_TYPE"};
	public static final String[] SUBCODE_MSG_OPEN = {"UN_VERSION", "BAD_AS", "BAD_ID",
													 "UN_PARAMETER", "AUTH_FAIL", "UN_HOLDTIME"};
	public static final String[] SUBCODE_MSG_UPDT = {"MALFORMED_ATTR", "UNRECO_WELLKNOWN_ATTR", "MISS_WELLKNOWN_ATTR",
													 "ATTR_FLAG_ERR", "ATTR_LEN_ERR", "INV_ORIG_ATTR",
													 "AS_ROUTE_LOOP", "INV_NHOP_ATTR", "OPT_ATTR_ERR",
													 "INV_NET_FIELD", "MALFORMED_AS_PATH"};

	// Values for Open, Update, Notification and Keepalive
	public static final int[] MIN_MSG_LENGTH = {29,23,21,19}; 
	public static final int MAX_LENGTH_MSG = 4096;
	public static final String HEADER_MARKER_HEX = Strings.repeat("ffff", 8);
	public static final byte[] HEADER_MARKER = BGPSecUtils.hexStrToByteArray(Strings.repeat("ffff", 8));
	public static final StringBuilder KEEPALIVE_MSG = new StringBuilder()
								.append(HEADER_MARKER_HEX).append("001304");
    
	
	public static StringBuilder MY_DEFAULT_OPEN_HEADER = new StringBuilder()
								.append(BGPSecUtils.decToHexWithPad(OPEN, 2))
								.append(BGPSecUtils.bytesToHex(MY_BGP_VERSION))
								.append(BGPSecUtils.decToHexWithPad(MY_ASN_16, 4))
								.append(BGPSecUtils.decToHexWithPad(DEFAULT_HOLD_TIME, 4))
								.append(BGPSecDefs.MY_ID);

	public static StringBuilder MY_OPEN_OPTIONAL_PARAM = new StringBuilder()
								.append("1802060104000100010202800002020200020641040000fde9");	
	
	public static HashMap<Integer, String> optCapCodes = new HashMap<Integer, String>();
	
	/* 
	 * Optional Capabilities Codes for Open Message
	 0	Reserved	[RFC5492]
	 1	Multiprotocol Extensions for BGP-4	[RFC2858]
	 2	Route Refresh Capability for BGP-4	[RFC2918]
	 3	Outbound Route Filtering Capability	[RFC5291]
	 4	Multiple routes to a destination capability (deprecated)	[RFC8277]
	 5	Extended Next Hop Encoding	[RFC5549]
	 6	BGP Extended Message	[RFC8654]
	 7	BGPsec Capability	[RFC8205]
	 8	Multiple Labels Capability	[RFC8277]
	 9	BGP Role (TEMPORARY - registered 2018-03-29, extension registered 2019-03-18, expires 2020-03-29)	[draft-ietf-idr-bgp-open-policy]
	 10-63	Unassigned	
	 64	Graceful Restart Capability	[RFC4724]
	 65	Support for 4-octet AS number capability	[RFC6793]
	 66	Deprecated (2003-03-06)	
	 67	Support for Dynamic Capability (capability specific)	[draft-ietf-idr-dynamic-cap]
	 68	Multisession BGP Capability	[draft-ietf-idr-bgp-multisession]
	 69	ADD-PATH Capability	[RFC7911]
	 70	Enhanced Route Refresh Capability	[RFC7313]
	 71	Long-Lived Graceful Restart (LLGR) Capability	[draft-uttaro-idr-bgp-persistence]
	 72	Unassigned	
	 73	FQDN Capability	[draft-walton-bgp-hostname-capability]
	 74-127	Unassigned	
	 128-255	Reserved for Private Use	[RFC5492]
	 */
	
	public BGPSecDefs() {
		optCapCodes.clear();
		setOptCapCodes();
	}
	
	public static void setOptCapCodes() {
		optCapCodes.put(1, "Multiprotocol Extensions for BGP-4");
		optCapCodes.put(2, "Route Refresh Capability for BGP-4");
		optCapCodes.put(3, "Outbound Route Filtering Capability");
		optCapCodes.put(5, "Extended Next Hop Encoding");
		optCapCodes.put(6, "BGP Extended Message");
		optCapCodes.put(7, "BGPsec Capability");
		optCapCodes.put(8, "Multiple Labels Capability");
		optCapCodes.put(9, "BGP Role");
		optCapCodes.put(64, "Graceful Restart Capability");
		optCapCodes.put(65, "Support for 4-octet AS number capability");
		optCapCodes.put(67, "Support for Dynamic Capability");
		optCapCodes.put(68, "Multisession BGP Capability");
		optCapCodes.put(69, "ADD-PATH Capability");
		optCapCodes.put(70, "Enhanced Route Refresh Capability");
		optCapCodes.put(71, "Long-Lived Graceful Restart (LLGR) Capability");
		optCapCodes.put(73, "FQDN Capability	[draft-walton-bgp-hostname-capability]");		
	}

										
	
	
}
