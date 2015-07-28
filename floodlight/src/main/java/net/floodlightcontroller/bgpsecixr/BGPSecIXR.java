package net.floodlightcontroller.bgpsecixr;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowRemoved;
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
import org.projectfloodlight.openflow.types.TransportPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.bgpsec.BGPSecDefs;
import net.floodlightcontroller.bgpsec.BGPSecHandle;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.debugcounter.IDebugCounterService;
import net.floodlightcontroller.learningswitch.LearningSwitch;
import net.floodlightcontroller.learningswitch.LearningSwitchWebRoutable;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;

public class BGPSecIXR implements IOFMessageListener, IOFSwitchListener, IFloodlightModule {
	protected IFloodlightProviderService floodlightProvider;
	protected static Logger log = LoggerFactory.getLogger(BGPSecIXR.class);
    // RPKI Cache
    public static HashMap<String, String[]> cacheMap = new HashMap<String, String[]>();
	// Module dependencies
	protected IFloodlightProviderService floodlightProviderService;
	protected IRestApiService restApiService;
	protected IStaticFlowEntryPusherService sfp;
	protected IOFSwitchService switchService;

	@Override
	public String getName() {
		return BGPSecIXR.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
	    Collection<Class<? extends IFloodlightService>> l =
	        new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
	    return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
		restApiService = context.getServiceImpl(IRestApiService.class);
		sfp = context.getServiceImpl(IStaticFlowEntryPusherService.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);
		//log = LoggerFactory.getLogger(BGPSecIXR.class);

	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProviderService.addOFMessageListener(OFType.FLOW_REMOVED, this);
		floodlightProviderService.addOFMessageListener(OFType.ERROR, this);
		//restApiService.addRestletRoutable(new LearningSwitchWebRoutable());
		switchService.addOFSwitchListener(this);

	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		switch (msg.getType()) {
		case PACKET_IN:
			Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
	        if (eth.getEtherType() == EthType.IPv4) {
	        	// Get IPv4 payload
	        	IPv4 ipv4 = (IPv4) eth.getPayload();
	        	IPv4Address srcIP = ipv4.getSourceAddress();
	        	if (ipv4.getProtocol().equals(IpProtocol.TCP)) {
	        		// Get TCP payload
	        		TCP tcp = (TCP) ipv4.getPayload();
	        		TransportPort srcPort = tcp.getSourcePort();
	        		TransportPort dstPort = tcp.getDestinationPort();
	        		if ((srcPort.equals(BGPSecIXRDefs.BGP_PORT)) || (dstPort.equals(BGPSecIXRDefs.BGP_PORT))) {
	        			log.info("BGP Packet received, payload: " + BGPSecIXRUtils.bytesToHexString(tcp.getPayload().serialize()));
	        			return Command.CONTINUE;	                
	        		}
	        	}
	        }			
	        return Command.CONTINUE;
					
		case FLOW_REMOVED:
			return Command.CONTINUE;
			
		case ERROR:
			log.info("received an error {} from switch {}", msg, sw);
			return Command.CONTINUE;
			
		default:
			log.error("received an unexpected message {} from switch {}", msg, sw);
			return Command.CONTINUE;
		}
	}

	@Override
	public void switchAdded(DatapathId dpid) {				
		IOFSwitch sw = switchService.getSwitch(dpid);
		for(int i=0; i < 2; i++) {
			OFFlowAdd.Builder flow = sw.getOFFactory().buildFlowAdd();
			Match.Builder match = sw.getOFFactory().buildMatch();
			ArrayList<OFAction> actionList = new ArrayList<OFAction>();
			OFActionOutput.Builder action = sw.getOFFactory().actions().buildOutput();

			match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
			match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
			if (i == 0)
				match.setExact(MatchField.TCP_SRC, BGPSecIXRDefs.BGP_PORT);
			else
				match.setExact(MatchField.TCP_DST, BGPSecIXRDefs.BGP_PORT);
			action.setMaxLen(0xffFFffFF);
			action.setPort(OFPort.CONTROLLER);
			actionList.add(action.build());
			
			flow.setBufferId(OFBufferId.NO_BUFFER);
			flow.setHardTimeout(0);
			flow.setIdleTimeout(0);
			flow.setOutPort(OFPort.CONTROLLER);
			flow.setActions(actionList);
			flow.setMatch(match.build());
			flow.setPriority(65000);
			sfp.addFlow("bg" + Integer.toString(i), flow.build(), sw.getId());	
		}
		log.info("Adding flow to redirect BGP port in the switch: " + dpid);
	}

	@Override
	public void switchRemoved(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchActivated(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchPortChanged(DatapathId switchId, OFPortDesc port,
			PortChangeType type) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchChanged(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}

}
