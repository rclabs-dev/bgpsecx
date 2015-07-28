package net.floodlightcontroller.bgpsec;

import org.projectfloodlight.openflow.types.TransportPort;

import com.google.common.base.Strings;

public class BGPSecDefs {
	public final static String RPKI_URL = "http://localhost:8081/api/v1/validity/";
	
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
	public static final String[] SUBCODE_MSG_UPDT = {"MALFORMED_ATTR", "UNRECO_WK_ATTR", "MISS_WK_ATTR",
													 "ATTR_FLAG_ERR", "ATTR_LEN_ERR", "INV_ORIG_ATTR",
													 "AS_ROUTE_LOOP", "INV_NHOP_ATTR", "OPT_ATTR_ERR",
													 "INV_NET_FIELD", "MALFORMED_AS_PATH"};
	public static final TransportPort BGP_PORT = TransportPort.of(179);
	public static final int[] MIN_LENGTH_MSG = {29,23,21,19};
	public static final int MAX_LENGTH_MSG = 4096;
	public static final byte[] HEADER_MARKER = BGPSecUtils
			.hexStrToByteArray(Strings.repeat("ffff", 8));
	public static final String HEADER_MARKERH = Strings.repeat("ffff", 8);
	public static final byte[] FAKE = BGPSecUtils
			.hexStrToByteArray("ffffffffffffffffffffffffffffffff003b020000001c400101005002000602010000022f400304ac1f01028004040000000018c1011618c10217");
	public static final byte[] FAKE2 = BGPSecUtils
			.hexStrToByteArray("ffffffffffffffffffffffffffffffff0037020000001c400101005002000602010000022f400304ac1f01028004040000000018c10216");
}
