package net.floodlightcontroller.bgpsecx;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.U64;

//import net.floodlightcontroller.bgpsecixr.general.*;

import java.util.ArrayList;
import java.util.Set;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchDriver;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.LogicalOFMessageCategory;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IAppHandshakePluginFactory;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.internal.OFSwitchHandshakeHandler;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
//import net.floodlightcontroller.core.rest.SwitchRepresentation;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.bgpsecx.general.BGPSecDefs;
//import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.bgpsecx.sessioncontrol.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BGPSecX implements IOFMessageListener, IFloodlightModule,  IOFSwitchService, IOFSwitchListener  {
	
	// TCP Server for communicate with speakers
	BGPSecTCPDaemon bgpServer = 
			new BGPSecTCPDaemon(BGPSecDefs.IP_TO_LISTEN, 
			    BGPSecDefs.BGP_PORT, BGPSecDefs.SOCKET_QUEUE);
	
	BGPSecWhatdog whatdog = new BGPSecWhatdog();

	// Setters and Getters for RS session data
	public static BGPSecSetGetSessionData sessionData = new BGPSecSetGetSessionData();
	
	// RPKI Cache
	private static HashMap<String, String[]> rpkiCacheMap = new HashMap<String, String[]>();
	
	/**
	 *  authPeers contains a list of authorized peers for establish BGP Session
	 *  Key and value contains the ASN and IP address of remote peer, respectively.
	 */
	private static HashMap<Integer, String> authPeers = new HashMap<Integer, String>();
	
	protected IFloodlightProviderService floodlightProvider;
	protected static Logger log;
	
	BGPSecPushPacketOut push = new BGPSecPushPacketOut();
	//protected BGPSecArpHandle arpHandle;
	
	//protected IStaticFlowEntryPusherService sfp;
	protected IOFSwitchService switchService;

	@Override
	public String getName() {
	    return BGPSecX.class.getSimpleName();
	}
	
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
	    Collection<Class<? extends IFloodlightService>> l =
	        new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
		//l.add(IStaticFlowEntryPusherService.class);
		l.add(IOFSwitchService.class);
	    return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
	    floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
	    log = LoggerFactory.getLogger(BGPSecX.class);
	    //sfp = context.getServiceImpl(IStaticFlowEntryPusherService.class);
	    switchService = context.getServiceImpl(IOFSwitchService.class);
	    sessionData.clearAllSessionData();
	    // List of authorized peers for establish BGP Session
	    authPeers.clear();
	    authPeers.put(65001, "ac110101");
	    authPeers.put(65002, "ac110102");
	    authPeers.put(65003, "ac110103");
	    authPeers.put(65004, "ac110104");
	    authPeers.put(65005, "ac110105");
	    authPeers.put(65006, "ac110106");
	    authPeers.put(65007, "ac110107");
	    authPeers.put(65008, "ac110108");
	    authPeers.put(65009, "ac110109");
	    authPeers.put(65010, "ac11010a");

	}

	@Override
	public void startUp(FloodlightModuleContext context) {
	    floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	    switchService.addOFSwitchListener(this);
	    // Start BGP Route Server to communicate with speaks
	  //  new Thread(bgpServer).start();
	    // Whatdog for BGP Route Server session timers
	 //   new Thread(whatdog).start();
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		OFPacketIn pkt = (OFPacketIn) msg;

		if (pkt.getCookie().equals(U64.of(1000))) {
			Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
					IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
			// Get IPv4 payload and IP Address
			IPv4 ipv4 = (IPv4) eth.getPayload();
			IPv4Address srcIP = ipv4.getSourceAddress();
			IPv4Address dstIP = ipv4.getDestinationAddress();
			// Get TCP payload and Ports
			TCP tcp = (TCP) ipv4.getPayload();		
			/* 
			 * Some TCP Flags:
			 * 01: FIN; 02: SYN; 04: RST; 16: ACK 
			 * 17: ACK-FIN; 18: ACK-SYN; 20: ACK-RST; 24: ACK-PUSH
			 */
					
			short tcpFlags = tcp.getFlags();
			log.info("TCP message from: " + srcIP.toString() + ", to: " + dstIP.toString());
			//log.info("TCP FLAG #" + tcpFlags + ", Payload: " + BGPSecUtils.bytesToHexString(tcp.serialize()));
					
			if (tcpFlags == 24) { // All BGP messages after connection are PSH-ACK
				//byte [] msgCheck = checkBGPMessage(tcp.getPayload().serialize());
				//log.info("BGP Result: " +  BGPSecUtils.bytesToHexString(bgpResult));
				//int typeMsg = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(msgCheck, 0, 1));
				//log.info("BGP Message type: " + BGPSecDefs.MSG_TYPE[typeMsg - 1]); 
				//if (typeMsg == BGPSecDefs.UPDATE) {
				//	log.info("BGP Message: " + BGPSecUtils.subByte(msgCheck, 1));
					//byte[] bgpResult = BGPSecUpdateHandler.processBGPPkt(BGPSecUtils.subByte(msgCheck, 1), srcIP);
				//}
			}
		} // if (pkt.getCookie().equals(U64.of(1000)))
		
		//push.forwardPacketInToSwitch(sw, pkt);
		
		return Command.CONTINUE;
    }

	/**
	 * Check if the TCP payload is a BGP message. If yes cut the 
	 * TCP header and BGP header marker and return: a concatenated 
	 * message which contains the type of message + BGP message 
	 * without marker. The type equal to 0, there not a BGP message 
	 * 
	 * @param pkt (a TCP payload) 
	 * @return  (type of message + BGP message without marker if is a valid message) 
	 */
/*	public static byte[] checkBGPMessage(byte[] pkt) {
	    byte[] tmp = null;
	    log.debug("RAW BGP message received: " + BGPSecUtils.bytesToHexString(pkt));
		if (pkt.length > 0) {
			if (Arrays.equals(BGPSecUtils.subByte(pkt, 0, 16), BGPSecDefs.HEADER_MARKER)) {
				tmp = BGPSecUtils.subByte(pkt, 16, pkt.length - 16);
			}
		} else {
			// There not exist a BGPMessage
			return new byte[] {0x00};
		}
		return BGPSecUtils.concatBytes(BGPSecUtils.subByte(tmp, 2, 1), tmp);
	}
*/

	@Override
	public Map<DatapathId, IOFSwitch> getAllSwitchMap() {
		return null;
	}

	@Override
	public IOFSwitch getSwitch(DatapathId dpid) {
		return null;
	}

	@Override
	public IOFSwitch getActiveSwitch(DatapathId dpid) {
		return null;
	}

	@Override
	public void addOFSwitchListener(IOFSwitchListener listener) {
		
	}

	@Override
	public void addOFSwitchDriver(String manufacturerDescriptionPrefix,
			IOFSwitchDriver driver) {
		
	}

	@Override
	public void removeOFSwitchListener(IOFSwitchListener listener) {
		
	}

	@Override
	public void registerLogicalOFMessageCategory(
			LogicalOFMessageCategory category) {
		
	}

	@Override
	public void registerHandshakePlugin(IAppHandshakePluginFactory plugin) {
		
	}

	@Override
	public Set<DatapathId> getAllSwitchDpids() {
		return null;
	}

	@Override
	public List<OFSwitchHandshakeHandler> getSwitchHandshakeHandlers() {
		return null;
	}

	@Override
	public void switchAdded(DatapathId switchId) {
		IOFSwitch ofSwitch = switchService.getSwitch(switchId);
		OFFactory ofFactory = ofSwitch.getOFFactory();
		for (int i = 0; i < 2; i++) {
			Match.Builder match = ofFactory.buildMatch();
			match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
			match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
	        //match.setExact(MatchField.IPV4_DST, IPv4Address.of("172.31.1.2"));	
			/*if (i == 0)
				match.setExact(MatchField.TCP_SRC, TransportPort.of(BGPSecDefs.BGP_PORT));
			else
				match.setExact(MatchField.TCP_DST, TransportPort.of(BGPSecDefs.BGP_PORT));		
			*/
			ArrayList<OFAction> actionList = new ArrayList<OFAction>();
			OFActionOutput.Builder actionOut = ofFactory.actions().buildOutput();
			actionOut.setMaxLen(0xffFFffFF);
			actionOut.setPort(OFPort.CONTROLLER);
			actionList.add(actionOut.build());
		    // Build flow three
			OFFlowAdd.Builder flow = ofFactory.buildFlowAdd();
			flow.setBufferId(OFBufferId.NO_BUFFER);
			flow.setHardTimeout(0);
			flow.setIdleTimeout(0);
			flow.setOutPort(OFPort.CONTROLLER);
			flow.setActions(actionList);
			flow.setMatch(match.build());
			flow.setPriority((short)32767);
			flow.setCookie(U64.of(1000));

			ofSwitch.write(flow.build());
		}
		log.info("Flow was installed to redirect BGP port to Controller in the switch: " + switchId);
	}

	@Override
	public void switchRemoved(DatapathId switchId) {
		
	}

	@Override
	public void switchActivated(DatapathId switchId) {
		
	}

	@Override
	public void switchPortChanged(DatapathId switchId, OFPortDesc port,
			PortChangeType type) {
		
	}

	@Override
	public void switchChanged(DatapathId switchId) {
		
	}
	
	public static void setROACache(String prefix, String asn, String ip) {
			rpkiCacheMap.put(prefix, new String[] {asn, ip});
			log.info("Adding new ROA " + asn + "/" + prefix + " in CACHE, from speaker " + 
			                    ip + ", cache size: " + rpkiCacheMap.size());
	}
	
	public static String[] getRPKICacheValue(String value) {
		return rpkiCacheMap.get(value);
	}
	
	public static int getRPKICacheSize() {
		return rpkiCacheMap.size();
	}

	public static void setRPKICacheClear() {
		rpkiCacheMap.clear();
	}
	
	public static boolean getRPKICacheContains(String prefix) {
		return rpkiCacheMap.containsKey(prefix);
	}

	public static String getAuthPeersValue(Integer asn){
		return authPeers.get(asn);
	}
	
	public static boolean containsPeer(Integer asn){
		return authPeers.containsKey(asn);
	}
	

	@Override
	public void switchDeactivated(DatapathId switchId) {
		
	}

}