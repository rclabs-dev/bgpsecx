package net.floodlightcontroller.bgpsecx.update;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.ArrayList;

import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.bgpsecx.general.BGPSecDefs;

public class BGPSecQueryRPKI {
	protected static Logger log = LoggerFactory
			.getLogger(BGPSecQueryRPKI.class);
	static ArrayList<String> prefixData = new ArrayList<String>();

	/**
	 * Verify ROA in cache and anchors database (RIPE RPKI Validator)
	 * 
	 * @param prefix is a prefix to validate associated with asn
	 * @param asn is a asn associated with prefix
	 * @param speaker is that generates the update;
	 * @param type is if route is withdraw or NLRI
	 * @return true if ROA is passed or false if ROA don't passed
	 */
	public static boolean roaValidator(String prefix, String asn,
			String speaker, int type) {
		log.info("Data to verify in Cache/Anchor, prefix: " + prefix + ", ASN: " + asn
				+ ", speaker: " + speaker + ", routeType: " + type);
		// type = 0 is Withdraw routes, where as type = 1 is NLRI routes
		if (type == 1) {
			// Check prefix in NLRI at RPKI Cache
			String asnPrefix = asn + "/" + prefix;
			log.info("NLRI to verify on RPKI: " + asnPrefix);

			if (!(BGPSecCacheRPKI.getROAOnCache(prefix, asn, ""))) {
				// Check prefix in RPKI Anchors database
				if (!(getROAStatus(asnPrefix))) {
					// Return false even whether at least of them is invalid
					log.info("ASN/Prefix NOT EXIST in DATABASE: " + asnPrefix);
					return false;
				} else {
					// Prefix found in RPKI database, add in RPKI Cache
					log.info("ASN/Prefix EXIST in DATABASE: " + asnPrefix);
					BGPSecCacheRPKI.setROAOnCache(prefix, asn, speaker);
				}
			}
		} else {
			// Check withdraw prefixes on RPKI Cache
			log.info("Withdraw routes to verify on CACHE: " + prefix
					+ ", Speaker:  " + speaker);
			if (!(BGPSecCacheRPKI.getROAOnCache(prefix, "", speaker)))
				return false;
		}
		return true;
	}

	/**
	 * HTTP request to RPKI and parse JSON result
	 * 
	 * @param url
	 * @return true if query is "valid" and false if "invalid" or "not found".
	 *         It's based in RFC6811.
	 */
	public static boolean getROAStatus(String data) {
		JSONObject mainObject;
		String resultRPKI = null;
		InputStream is = null;
		try {
			is = new URL((BGPSecDefs.RPKI_URL + data)).openStream();
			StringBuilder sb = new StringBuilder();
			int cp;
			BufferedReader rd = new BufferedReader(new InputStreamReader(is,
					Charset.forName("UTF-8")));
			while ((cp = rd.read()) != -1) {
				sb.append((char) cp);
			}
			JSONObject json = null;
			json = new JSONObject(sb.toString());
			mainObject = (JSONObject) json.get("validated_route");
			JSONObject validityObj = (JSONObject) mainObject.get("validity");
			resultRPKI = validityObj.getString("state");

		} catch (MalformedURLException e) {
			log.info("MalformedURL Error em JSON Parser!");
			// e.printStackTrace();
		} catch (IOException e) {
			log.info("I/O Error em JSON Parser!");
			// e.printStackTrace();
		} catch (JSONException e) {
			log.info("JSON Error em JSON Parser!");
			// e.printStackTrace();
		}

		if (resultRPKI.equals("Valid"))
			return true;
		return false;
	}

}
