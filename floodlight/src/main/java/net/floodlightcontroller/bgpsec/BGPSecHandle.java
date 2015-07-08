package net.floodlightcontroller.bgpsec;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BGPSecHandle extends BGPSecDefs {
	protected static Logger log = LoggerFactory.getLogger(BGPSecHandle.class);
	/*
	 * attrData keys contain: 0: Total message length 1: Withdrawn routes 2:
	 * ORIGIN type 3: AS_PATH segment type 4: First ASN in AS_PATH 5: Last ASN
	 * in AS_PATH 6: Chain of the ASNs in AS_PATH 7: NEXT_HOP 8: NLRI
	 */
	static Hashtable<Integer, byte[]> attrData = new Hashtable<Integer, byte[]>();

	public static boolean processBGPPkt(byte[] bgpMsg, IPv4Address speakerIP) {

		// If the message don't have a HEADER MARK or is equal null don't treat 
		// the message and pass through. It prevent some situation associated 
		// with any vulnerabilities
		if (bgpMsg.length > 0) {
			if(!containsMark(bgpMsg))
				return true;
		} else {
			return true;
		}
		
		long startTime = System.currentTimeMillis();
		List<byte[]> msgs = new ArrayList<>();
		List<byte[]> validPrefixes = new ArrayList<>();
		int totUpdtMsg;
		boolean roaResult;

		log.info("BGP message payload: " + BGPSecUtils.bytesToHexString(bgpMsg));

		// A TCP stream can have several chain messages. It check whether in the
		// message have more that one BGP Update Messages in stream
		msgs = getAllUpdtMsg(bgpMsg);
		
		// If message is not a message of type update, the msgs return 0
		if ((totUpdtMsg = msgs.size()) == 0) {
			totUpdtMsg = 1;
		}
		
		log.info("Number of BGP Update messages in stream: " + totUpdtMsg);

		// Process the total of BGP Update messages that exist in the stream
		for (int i = 0; i < totUpdtMsg; i++) {
			if (totUpdtMsg > 1) {
				bgpMsg = BGPSecUtils.cloneArray(msgs.get(i));
				log.info("BGP Update message to verify: "
						+ BGPSecUtils.bytesToHexString(bgpMsg));
			}

			// Get BGP message type
			int msg = getTypeMsg(bgpMsg);
			log.info("Received a BGP message, type: " + MSG_TYPE[msg]
					+ ", from: " + speakerIP.toString());

			// Parse BGP Update message
			if (msg == UPDATE && checkMsgLength(bgpMsg) ) {
				/* attrData keys returns the following data:
				 * 0: Total message length; 1: Withdrawn routes
				 * 2: ORIGIN type; 3: AS_PATH segment type
				 * 4: First ASN in AS_PATH; 5: Last ASN in AS_PATH
				 * 6: Chain of the ASNs in AS_PATH
				 * 7: NEXT_HOP; 8: NLRI
				 */
				attrData = BGPSecUpdateParser.msgParser(removeMark(bgpMsg));

				String prefChain = null;
				// Get last ASN in the update message
				String asNumber = Integer.toString(BGPSecUtils
						.bytesToInt(attrData.get(5)));
				// define default value of flag as withdraw routes
				int routeType = 0; 

				// Verify whether there Witdrawn Routes in BGP Message
				if (attrData.containsKey(2)) {
					prefChain = BGPSecUtils.bytesToHexString(attrData.get(2));
				}

				// Verify whether there NLRI Routes in BGP Message
				if (attrData.containsKey(8)) {
					prefChain = BGPSecUtils.bytesToHexString(attrData.get(8));
					routeType = 1; // For NLRI routes
				}

				// Verify ROA on RPKI database
				log.info("Data before ROA verify, prefChain:  " + prefChain
						+ ", asNumber: " + asNumber + ", speaker: " + speakerIP
						+ ", routeType: " + routeType);
				roaResult = BGPSecQueryRPKI.roaValidator(prefChain, asNumber,
						speakerIP.toString(), routeType);
				log.info("RESULT of ROA Validadtor is: " + roaResult);

				// Debug 
				long elapsedTime = System.currentTimeMillis() - startTime;
				log.info("Time last for verify a msg: " + elapsedTime);
				
				// Debug
				/*
				 * for (int i=0; i < 9; i++) { if (attrData.containsKey(i))
				 * System.out.println("Key: " + i + ", Value: " +
				 * BGPSecUtils.bytesToHexString(attrData.get(i)));
				 * 
				 * }
				 */
			}
		}
		return true;
	}

	/**
	 * Verify whether more that one update menssage in payload If there,
	 * disjoint them for parse separately
	 * 
	 * @param stream
	 * @return
	 */
	public static List<byte[]> getAllUpdtMsg(byte[] msg) {
		List<byte[]> msgs = new ArrayList<byte[]>();
		int flag = 0;

		while (flag == 0) {
			int lenMsg = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(msg, 16,
					2));
			if (getTypeMsg(msg) == 2)
				msgs.add(BGPSecUtils.subByte(msg, 0, lenMsg));

			if (msg.length == lenMsg) {
				// There only one message in stream or is the last message
				flag = 1;
			} else { // There several BGP messages in stream
				msg = BGPSecUtils.subByte(msg, lenMsg);
			}
		}
		return msgs;
	}

	/**
	 * Verify whether message contains the BGP header mark
	 * 
	 * @param msg
	 * @return
	 */
	public static boolean containsMark (byte[] msg) {
		if (msg.length < MIN_LENGTH_MSG) {
			return false;
		}
		if (Arrays.equals(BGPSecUtils.subByte(msg, 0, 16), HEADER_MARKER))
			return true;
		return false;			
	}
	
	/**
	 * Verify whether the length of message agrees with RFC 
	 * @param msg
	 * @return
	 */
	public static boolean checkMsgLength(byte[] msg) {
		int len = msg.length;
		if (len < MIN_LENGTH_MSG || len > MAX_LENGTH_MSG) {
			return false;
		}
		return true;
	}
	
	/**
	 * Return the message without BGP header mark
	 * @param msg
	 * @return
	 */
	public static byte[] removeMark(byte[] msg) {
		return BGPSecUtils.subByte(msg, 16, msg.length - 16);
	}
	
	/**
	 * Return the type of message
	 * @param msg
	 * @return
	 */
	public static int getTypeMsg(byte[] msg) {
		return BGPSecUtils.bytesToInt(BGPSecUtils.subByte(msg, 18, 1));
	}
}