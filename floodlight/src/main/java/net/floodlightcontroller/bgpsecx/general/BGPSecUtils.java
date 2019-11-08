package net.floodlightcontroller.bgpsecx.general;

import java.nio.ByteBuffer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BGPSecUtils {

	/*
    public static Boolean getBit(byte b, int bit){
        return (b & (1 << bit)) != 0;
    }*/
	
	/** 
	 * Convert Hex to binary and pad with zero if need to complete one octect
	 * Use to decode "Total Path Attribute Length" bits
	 * @param hexNumber
	 * @return
	 */
	public static boolean isBit(byte[] num, int pos){       
        String binFlags = Integer.toBinaryString((bytesToInt(num)));
        while (binFlags.length() < 8){
           binFlags = "0" + binFlags;
        }
        //System.out.println("Flags in binary: "  + binFlags);
		if (binFlags.substring(pos,pos+1).equals("1"))
			return true;
        return false;
	}
	
	/** 
	 * Convert Hex to binary and pad with zero if need to complete one octect
	 * For use to decode "Total Path Attribute Length" bits
	 * @param hexNumber
	 * @return
	 */
	public static String bitFlags(String hexNumber){       
        String binFlags = Integer.toBinaryString((hexToDec(hexNumber)));
        while (binFlags.length() < 8){
           binFlags = "0" + binFlags;
        }
        //System.out.println("Flags in binary: "  + binFlags);
		return binFlags.substring(3,4);
	}	
	
	/**
	 * Convert Hex to Decimal
	 * @param hexNumber
	 * @return
	 */
	public static int hexToDec(String hexNumber) {
		return Integer.parseInt(hexNumber, 16);
	}
		
	private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
	
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for (int j = 0; j < bytes.length; j++) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = HEX_ARRAY[v >>> 4];
	        hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	
	/**
	 * Returns a new byte array from given byte array, starting at start index with the size of the length parameter.
	 * Byte array given as parameter stays untouched.
	 *
	 * @param bytes original byte array
	 * @param startIndex beginning index, inclusive
	 * @param length how many bytes should be in the sub-array
	 * @return a new byte array that is a sub-array of the original
	 */
	public static byte[] subByte(final byte[] bytes, final int startIndex, final int length) {
		if (!checkLength(bytes, length) || !checkStartIndex(bytes, startIndex, length)) {
			throw new IllegalArgumentException("Cannot create subByte, invalid arguments: Length: " + length + " startIndex: " + startIndex);
	    }
	    final byte[] res = new byte[length];
	    System.arraycopy(bytes, startIndex, res, 0, length);
	    return res;
	}		
	    
	private static boolean checkLength(final byte[] bytes, final int length) {
	    return length > 0 && bytes.length > 0 && length <= bytes.length;
	}

	private static boolean checkStartIndex(final byte[] bytes, final int startIndex, final int length) {
	    return startIndex >= 0 && startIndex < bytes.length && (startIndex + length <= bytes.length);
	}

	/**
	 * Converts byte array to Integer. If there are less bytes in the array as required (4), the method will push
	 * adequate number of zero bytes prepending given byte array.
	 *
	 * @param bytes array to be converted to int
	 * @return int
	*/
	public static int bytesToInt(final byte[] bytes) {
		if (bytes.length > Integer.SIZE / Byte.SIZE) {
			throw new IllegalArgumentException("Cannot convert bytes to integer. Byte array too big.");
	    }
	    byte[] res = new byte[Integer.SIZE / Byte.SIZE];
	    if (bytes.length != Integer.SIZE / Byte.SIZE) {
	    	System.arraycopy(bytes, 0, res, Integer.SIZE / Byte.SIZE - bytes.length, bytes.length);
	    } else {
	        res = bytes;
	    }
	    final ByteBuffer buff = ByteBuffer.wrap(res);
	    	return buff.getInt();
	    }
		
	/**
	 * Check if everything in the string is number
	 * @param typeField a string with two bytes that contains type of message
	 * @return true if everything is a number or false if otherwise
	 */
	public static boolean isNumber(String typeField) {  
		for (int i = 0; i < typeField.length(); i++)
			if (!(Character.isDigit(typeField.charAt(i))))   
				return false;  
			return true;  
	}  	
	
	public static void getBytes(byte[] source, int srcBegin, int srcEnd, byte[] destination,
		     int dstBegin) {
		   System.arraycopy(source, srcBegin, destination, dstBegin, srcEnd - srcBegin);
		 }
	

		 /**
		  * Return a new byte array containing a sub-portion of the source array
		  * 
		  * @param srcBegin
		  *          The beginning index (inclusive)
		  * @param srcEnd
		  *          The ending index (exclusive)
		  * @return The new, populated byte array
		  */
		 public static byte[] subbytes(byte[] source, int srcBegin, int srcEnd) {
		   byte destination[];
		   destination = new byte[srcEnd - srcBegin];
		   getBytes(source, srcBegin, srcEnd, destination, 0);
		   return destination;
		 }

		 /**
		  * Return a new byte array containing a sub-portion of the source array
		  * 
		  * @param srcBegin
		  *          The beginning index (inclusive)
		  * @return The new, populated byte array
		  */
		 public static byte[] subByte(byte[] source, int srcBegin) {
		   return subbytes(source, srcBegin, source.length);
		 }	
		 
		 public static boolean isIPv4AddressValid(String cidr) {
			 if(cidr == null) {
				 return false;
			 }

			 String values[] = cidr.split("/");
			 Pattern ipv4Pattern = Pattern
					 .compile("(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])");
			 Matcher mm = ipv4Pattern.matcher(values[0]);
			 
			 if(!mm.matches()) {
				 return false;
			 }
			 
			 if(values.length >= 2) {
			 int prefix = Integer.valueOf(values[1]);
			 	if((prefix < 0) || (prefix > 32)) {
			 		return false;
			    }
			 }
			 return true;
		 }		 

		/**
		 * Convert hex IP Address format to conventional format  (decimal)
		 * @param ip
		 * @return
		 */
		 public static String ipHexToDec(String ip) {
			Long ipLong = Long.parseLong(ip, 16);
			String ipString = String.format("%d.%d.%d.%d", ipLong >> 24, 
			ipLong >> 16 & 0x00000000000000FF, 
			ipLong >> 8 & 0x00000000000000FF, 
			ipLong & 0x00000000000000FF);
			return ipString;
		}
		
			/**
			 * Convert decimal IP Address format to hexadecimal format
			 * @param ip
			 * @return
			 */		 
		public static String ipDecToHex(String ip) {
			 long result = 0;
			 String[] octects = ip.split("\\.");
			 for (int i = 3; i >= 0; i--)
				 result |= (Long.parseLong(octects[3 - i]) << (i * 8));
			 return Long.toHexString(result & 0xFFFFFFFF);
		 }

		/**
		 * Convert byte IP Address format to conventional format (decimal)
		 * @param ip
		 * @return
		 */		
		public static String ipByteToDec(byte[] ip) {
			return ipDecToHex(bytesToHex(ip));
		}		
		
		/**
		 * Convert hexadecimal IP Address to byte format
		 * @param ip
		 * @return
		 */				
		public static byte[] hexStrToByteArray(String s) {
		    byte data[] = new byte[s.length()/2];
		    for(int i=0;i < s.length();i+=2) {
		        data[i/2] = (Integer.decode("0x"+s.charAt(i)+s.charAt(i+1))).byteValue();
		    }
		    return data;
		}
		
		static public byte[] cloneArray(byte[] byteValue) {
			    byte[] b = new byte[byteValue.length];
			    System.arraycopy(byteValue, 0, b, 0, byteValue.length);
			    return b;
			  }
		
		public static byte[] concatBytes(byte[] a, byte[] b) {
			byte[] c = new byte[a.length + b.length];
			System.arraycopy(a, 0, c, 0, a.length);
			System.arraycopy(b, 0, c, a.length, b.length);
			return c;
		}
		
		public static String decToHexWithPad(Integer num, Integer padLimit) {
			return String.format("%0" + padLimit + "x", num);
		}
}
