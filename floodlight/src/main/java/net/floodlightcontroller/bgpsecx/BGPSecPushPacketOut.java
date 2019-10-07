package net.floodlightcontroller.bgpsecx;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.Ethernet;

import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;

public class BGPSecPushPacketOut {
	protected static Logger log;
		
	/**
	 * Writes an OFPacketOut message to a switch.
	 * 
	 * @param sw
	 *            The switch to write the PacketOut to.
	 * @param packetInMessage
	 *            The corresponding PacketOut.
	 */
	public void forwardPacketInToSwitch(IOFSwitch sw, OFPacketIn packetOutMessage) {
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();

		// Set buffer_id, in_port, actions_len
		pob.setBufferId(packetOutMessage.getBufferId());
		pob.setInPort(packetOutMessage.getVersion().compareTo(OFVersion.OF_12) < 0 ? packetOutMessage
				.getInPort() : packetOutMessage.getMatch().get(
				MatchField.IN_PORT));

		// set actions
		List<OFAction> actions = new ArrayList<OFAction>(1);
		actions.add(sw.getOFFactory().actions().buildOutput()
				.setPort(OFPort.FLOOD).setMaxLen(0xffFFffFF).build());
		pob.setActions(actions);

		// set data - only if buffer_id == -1
		if (packetOutMessage.getBufferId() == OFBufferId.NO_BUFFER) {
			byte[] packetData = packetOutMessage.getData();
			pob.setData(packetData);
		}

		// Write packet out
		sw.write(pob.build()); 
	}
	
	public void sendNewPacketToSwitch(IOFSwitch sw, Ethernet l2Packet) {
		OFPacketOut po = sw.getOFFactory().buildPacketOut() 
    	    .setData(l2Packet.serialize())
    	    .setActions(Collections.singletonList((OFAction) 
    	    		sw.getOFFactory().actions().output(OFPort.FLOOD, 0xffFFffFF)))
    	    .setInPort(OFPort.CONTROLLER)
    	    .build();
    	sw.write(po);
	}
}
