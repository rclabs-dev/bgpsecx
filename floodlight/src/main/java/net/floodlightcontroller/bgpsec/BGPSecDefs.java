package net.floodlightcontroller.bgpsec;

import org.projectfloodlight.openflow.types.TransportPort;

public class BGPSecDefs {
	
	public static final String[] MSG_TYPE = {"UNKNOWN", "OPEN", "UPDATE", "NOTIFICATION", "KEEPALIVE", "ROUTE-REFRESH"};
	public static final int OPEN = 1;
	public static final int UPDATE = 2;
	public static final int NOTIFICATION = 3;
	public static final int KEEPALIVE = 4;
	public static final int ROUTE_REFRESH = 5;

	public static final int ORIGIN = 1;
	public static final int AS_PATH = 2;
	public static final int NEXT_HOP = 3;

	public static final String[] ATTR_TYPE     = {"MULT_EXIT_DISC", "LOCAL_PREF", "ATOMIC_AGGREGATE", 
        								   "AGGREGATE", "COMMUNITY", "ORIGINATOR_ID", "CLUSTER_LIST"};
    public static final String[] ORIGIN_VALUE  = {"IGP", "EGP", "INCOMPLETE"};
    public static final String[] SEGMENT_TYPE = {"AS_SET", "AS_SEQUENCE"};
    public static final TransportPort LISTEN_PORT = TransportPort.of(179);
    public static final int MIN_LENGTH_MSG = 19; 
    public static final int MAX_LENGTH_MSG = 4096;


}
