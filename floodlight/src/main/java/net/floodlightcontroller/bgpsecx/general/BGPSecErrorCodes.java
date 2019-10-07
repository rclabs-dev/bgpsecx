package net.floodlightcontroller.bgpsecx.general;

public class BGPSecErrorCodes {
	// Group that defines the types of BGP Messages
	public static final byte OPEN = 1;
	public static final byte UPDATE = 2;
	public static final byte NOTIFICATION = 3;
	public static final byte KEEPALIVE = 4;
	public static final byte ROUTE_REFRESH = 5;
	
    // Code errors for the HEADER
	public static final byte HEADER_ERROR = 1;
    public static final byte HDR_SUB_UNSYNC = 1;
    public static final byte HDR_SUB_BAD_MSG_LEN = 2;
    public static final byte HDR_SUB_BAD_MSG_TYPE = 3;

    // Code errors for OPEN message
	public static final byte OPEN_ERROR = 2;
	public static final byte OPEN_SUB_UNSUPPORTED_VERSION = 1;
	public static final byte OPEN_SUB_BAD_AS = 2;
	public static final byte OPEN_SUB_BAD_ID = 3;
	public static final byte OPEN_SUB_UNSUPPORTED_PARAMETER = 4;
	public static final byte OPEN_SUB_AUTH_FAIL = 5;
	public static final byte OPEN_SUB_UNSUPPORTED_HOLDTIME = 6;
	
	// Code errors for UPDATE message
	public static final byte UPDATE_ERROR = 3;
	public static final byte UPDT_SUB_MALFORMED_ATTR = 1;
	public static final byte UPDT_SUB_UNRECO_WELLKNOWN_ATTR = 2;
	public static final byte UPDT_SUB_MISS_WELLKNOWN_ATTR = 3;
	public static final byte UPDT_SUB_ATTR_FLAG_ERROR = 4;
	public static final byte UPDT_SUB_ATTR_LEN_ERROR = 5;
	public static final byte UPDT_SUB_INV_ORIGIN_ATTR = 6;
	public static final byte UPDT_SUB_AS_ROUTE_LOOP = 7;
	public static final byte UPDT_SUB_INVALID_NHOP_ATTR = 8;
	public static final byte UPDT_SUB_OPT_ATTR_ERROR = 9;
	public static final byte UPDT_SUB_INVALID_NET_FIELD = 10;
	public static final byte UPDT_SUB_MALFORMED_AS_PATH = 11;
	
	// Code errors for HOLD TIME EXPIRED message
	public static final byte HOLD_TIMER_EXPIRED = 4;
	
	// Code errors for FSM message
	public static final byte FSM_ERROR = 5;
	
	// Code errors for CEASE message
	public static final byte CEASE = 6;
    	
	public static final String[] SUBCODE_HEADER_MSG = {"UNSYNC", "BAD_MSG_LENGTH", "BAD_MSG_TYPE"};
	public static final String[] SUBCODE_OPEN_MSG = {"UNSUPPORTED_VERSION", "BAD_AS", "BAD_ID",
			 										 "UNSUPPORTED_PARAMETER", "AUTH_FAIL", "UNSUPPORTED_HOLDTIME"};
	public static final String[] SUBCODE_UPDATE_MSG = {"MALFORMED_ATTR", "UNRECO_WELLKNOWN_ATTR", "MISSING_WELLKNOWN_ATTR",
			 										  "ATTR_FLAG_ERROR", "ATTR_LENGTH_ERROR", "INVALID_ORIGIN_ATTR",
			 										  "AS_ROUTE_LOOP", "INVALID_NEXHOP_ATTR", "OPTIONAL_ATTR_ERROR",
			 										  "INVALID_NET_FIELD", "MALFORMED_AS_PATH"};

}
