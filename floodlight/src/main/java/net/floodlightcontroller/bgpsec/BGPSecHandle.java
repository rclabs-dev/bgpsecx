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

	public static byte[] processBGPPkt(byte[] bgpMsg, IPv4Address speakerIP) {

		// If the message don't have a HEADER MARK or is equal null don't treat
		// the message and pass through. It prevent some situation associated
		// with any vulnerabilities
		if (bgpMsg.length > 0) {
			if (!containsMark(bgpMsg))
				return BGPSecUtils.hexStrToByteArray("01");
		} else {
			return BGPSecUtils.hexStrToByteArray("01");
		}

		long startTime = System.currentTimeMillis();
		// "msgs" there area individual updt msg of concatened updt msgs
		List<byte[]> msgs;
		List<String> prefixes = new ArrayList<>();
		List<String> validNLRI = new ArrayList<>();
		List<String> validWITH = new ArrayList<>();
		List<String> newPayloads = new ArrayList<>();
		String temp = "";
		String payTemp = "";
		boolean roaResult;

		log.info("New BGP message received: "
				+ BGPSecUtils.bytesToHexString(bgpMsg));

		// A TCP stream can have several chain messages. It check whether in the
		// message have more that one BGP update messages in stream
		msgs = getAllUpdtMsg(bgpMsg);

		int totUpdtMsg = msgs.size(); // # of concatened updt messages

		// If message is not a update message, the msgs return 0
		if (totUpdtMsg == 0) {
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
			log.info("Received a BGP message, type: " + MSG_TYPE[msg - 1]
					+ ", from: " + speakerIP.toString());
            boolean msgLen = checkMsgLength(bgpMsg, msg - 1);
            
			/****************************************************
			 * Makes the treatment of BGP UPDATE Messages       *
			 ***************************************************/
			if (msg == UPDATE && msgLen) {
				/*
				 * attrData keys returns the following data: 0: Total message
				 * length 1: Withdrawn routes with length 2: ORIGIN type 3:
				 * AS_PATH segment type 4: First ASN in AS_PATH 5: Last ASN in
				 * AS_PATH 6: Chain of the ASNs in AS_PATH 7: NEXT_HOP 8: NLRI
				 * 9: Fully Total Path Attr. length + Path Attr.
				 */
				attrData = BGPSecUpdateParser.msgParser(removeMark(bgpMsg));

				// For debug Parsed update message data
				// for (int i=0; i < 9; i++) { if (attrData.containsKey(i))
				// log.info("Key: " + i + ", Value: " +
				// BGPSecUtils.bytesToHexString(attrData.get(i)));
				// }

				String asNumber = null;
				String prefChain = null;
				int totPrefixNLRI = 0;
				int totPrefixWITH = 0;
				prefixes.clear();
				validNLRI.clear();
				validWITH.clear();

				// Verify whether there are Witdrawn Routes in BGP Message
				// If yes, validate this information only the cache with
				// associated IP address
				if (attrData.containsKey(1)) {
					prefChain = BGPSecUtils.bytesToHexString(BGPSecUtils
							.subByte(attrData.get(1), 2));
					log.info("WITHDRAW prefix chain: " + prefChain);
					prefixes = BGPSecPrefixChainParser.prefixParser(prefChain);
					for (int j = 0; j < prefixes.size(); j += 2) {
						roaResult = BGPSecQueryRPKI.roaValidator(
								prefixes.get(j), asNumber,
								speakerIP.toString(), 0);
						log.info("RESULT of WITHDRAW routes Validadtor is: *** "
								+ roaResult + " ***");
						totPrefixWITH++;
						if (roaResult)
							validWITH.add(prefixes.get(j + 1));
					}
				}

				// Verify whether there are NLRI Routes in BGP Message
				// If yes, validate this information in cache and anchors
				// database
				if (attrData.containsKey(8)) {
					// Get last ASN in the update message
					asNumber = Integer.toString(BGPSecUtils.bytesToInt(attrData
							.get(5)));
					prefChain = BGPSecUtils.bytesToHexString(attrData.get(8));
					log.info("NLRI prefix chain: " + prefChain);
					prefixes = BGPSecPrefixChainParser.prefixParser(prefChain);
					for (int j = 0; j < prefixes.size(); j += 2) {
						roaResult = BGPSecQueryRPKI.roaValidator(
								prefixes.get(j), asNumber,
								speakerIP.toString(), 1);
						log.info("RESULT of NLRI routes Validadtor is: *** "
								+ roaResult + " ***");
						totPrefixNLRI++;
						if (roaResult)
							validNLRI.add(prefixes.get(j + 1));
					}
				}

				int totNLRI = validNLRI.size();
				int totWITH = validWITH.size();

				// For debug valid routes
				log.info("Valid WITHDRAWN: ");
				for (String eachPrefix : validWITH) {
					log.info(eachPrefix);
				}

				log.info("Valid NLRI: ");
				for (String eachPrefix : validNLRI) {
					log.info(eachPrefix);
				}

				log.info("Values of totUpdtMsg; " + totUpdtMsg
						+ ", totPrefixNLRI: " + totPrefixNLRI
						+ ", totPrefixWITH: " + totPrefixWITH);
				log.info("Total of validNLRI: " + totNLRI + ", and validWITH: "
						+ totWITH);

				// There are a unique update message in stream
				// All NLRI or Withdrawn routes in update message is valid
				if ((i + 1) == totUpdtMsg && newPayloads.size() == 0) {
					if (totPrefixNLRI == totNLRI && totPrefixWITH == totWITH) {
						log.info("Return TRUE (1) without rebuild payload!");
						return BGPSecUtils.hexStrToByteArray("01");
					}
					// There are nothing valid NLRI or Withdraw routes in update
					// message
					if (totNLRI == 0 && totWITH == 0) {
						log.info("Return FALSE (0) without rebuild payload!");
						return BGPSecUtils.hexStrToByteArray("00");
					}
				}

				// The code below rebuild payload
				temp = "";
				payTemp = "";
				if (totNLRI != 0 || totWITH != 0) {
					if (totWITH != 0) {
						for (String value : validWITH) {
							temp = temp + value;
						}
						// Add withdrawn routes, but before add the message type
						payTemp = "02" + String.format("%04X", temp.length())
								+ temp;
					} else {
						// There are no withdrawn routes
						payTemp = "020000";
					}

					// Add Path Attributes and NLRI
					if (attrData.get(9).length != 0) {
						payTemp = payTemp
								+ BGPSecUtils.bytesToHexString(attrData.get(9));
						temp = "";
						for (String value : validNLRI) {
							temp = temp + value;
						}
						payTemp = payTemp + temp;
					}

					// The number 18 below is the length of header mark +
					// the total length of message which is added after
					String msgLength = String.format("%04X",
							((payTemp.length() / 2) + 18));
					payTemp = BGPSecDefs.HEADER_MARKERH + msgLength + payTemp;

					newPayloads.add(payTemp);
					log.info("New Payload " + (i + 1) + "/" + totUpdtMsg + ": "
							+ payTemp + ", length: " + payTemp.length());
				} // if (totNLRI != 0 || totWITH != 0)

			} // if (msg == UPDATE && checkMsgLength(bgpMsg))
			
			
			/****************************************************
			 * Makes the treatment of BGP NOTIFICATION Messages *
			 ***************************************************/
			if (msg == NOTIFICATION && msgLen) {
				int code = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(bgpMsg, 19, 1));
				int subcode = BGPSecUtils.bytesToInt(BGPSecUtils.subByte(bgpMsg, 20, 1));
				log.info("NOTIFICATION message code: " + NOTIFY_CODE[code - 1] + 
						 ", subcode: " + subcode);
				
			} // (msg == NOTIFICATION && msgLen)

			// Debug time for each update message
			long elapsedTime = System.currentTimeMillis() - startTime;
			log.info("Time last for verify a msg: " + elapsedTime);

		} // loop for (int i = 0; i < totUpdtMsg; i++)

		
		payTemp = "01"; // Default byte flag
		
		// There are leastwise one rebuilded message
		if (newPayloads.size() > 0) {
			payTemp = "03"; // Byte flag
			for (String payload : newPayloads) {
				if (payload.length() <= BGPSecDefs.MAX_LENGTH_MSG) {
					payTemp = payTemp + payload;
				} else {
					log.info("Exist a payload that exceeds the max length message: "
							+ payload);
				}
			}
		}
		
		return BGPSecUtils.hexStrToByteArray(payTemp);

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
			int lenMsg = BGPSecUtils
					.bytesToInt(BGPSecUtils.subByte(msg, 16, 2));
			if (getTypeMsg(msg) == 2)
				msgs.add(BGPSecUtils.subByte(msg, 0, lenMsg));

			if (msg.length == lenMsg) {
				// There only one message in stream or is the last message
				flag = 1;
			} else { // There several BGP messages in stream; get next one
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
	public static boolean containsMark(byte[] msg) {
		// MIN_LENGTH_MSG[3] is keepalive
		if (msg.length < MIN_LENGTH_MSG[3]) {
			return false;
		}
		if (Arrays.equals(BGPSecUtils.subByte(msg, 0, 16), HEADER_MARKER))
			return true;
		return false;
	}

	/**
	 * Verify whether the length of message agrees with RFC
	 * 
	 * @param msg
	 * @return
	 */
	public static boolean checkMsgLength(byte[] msg, int minLen) {
		int len = msg.length;
		if (len < MIN_LENGTH_MSG[minLen] || len > MAX_LENGTH_MSG) {
			return false;
		}
		return true;
	}

	/**
	 * Return the message without BGP header mark
	 * 
	 * @param msg
	 * @return
	 */
	public static byte[] removeMark(byte[] msg) {
		return BGPSecUtils.subByte(msg, 16, msg.length - 16);
	}

	/**
	 * Return the type of message
	 * 
	 * @param msg
	 * @return
	 */
	public static int getTypeMsg(byte[] msg) {
		return BGPSecUtils.bytesToInt(BGPSecUtils.subByte(msg, 18, 1));
	}
}