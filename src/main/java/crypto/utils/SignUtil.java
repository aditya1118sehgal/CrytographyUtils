package crypto.utils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Formatter;
import java.util.UUID;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Base64URL;

/**
 * This is a utility class for encrypting data
 * It uses HMACSHA-256
 * 
 * It can verify the encrypted data as well.
 * 
 * @author Aditya Sehgal
 */
public class SignUtil {

	// strings:
	// algorithm
	private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
	// JSON data key names:
	private static final String KEY_CNONCE = "cnonce";
	private static final String KEY_TIME_STAMP = "timeStamp";
	private static final String KEY_CLIENT_ID = "clientId";
	private static final String KEY_USER_ID = "userId";
	// member data:
	private String key;
	private String data;
	private String clientId;
	private String clientNonce;
	private String userId;
	private String timeStamp;
	private String encrypted;
	private byte[] encryptedBytes;
	private String encryptedData;
	
	public SignUtil (String key, String clientId, String userId) {
		this.key = key;
		this.clientId = clientId;
		this.userId = userId;
		this.generateCnonce();
	}

	/**
	 * Performs verification to ensure data was not corrupted
	 * 
	 * @return true if verified, false otherwise
	 */
	public boolean verify() throws JOSEException{
		MACVerifier verifier = new MACVerifier(this.key.getBytes());
		JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
		return verifier.verify(header, data.getBytes(), Base64URL.encode(encryptedBytes) );	
	}

	/** 
	 * Generates a random UUID 
	 * Assigns to cnonce
	 */
	private void generateCnonce() {
		this.clientNonce = UUID.randomUUID().toString();
	}

	/**
	 * Initialzes the object
	 * Obtains current time stamp
	 * and builds JSON data
	 */
	public void init() {
		this.obtainTimeStamp();
		this.buildJsonData();
	}
	
	/**
	 * Builds data as a String as JSON
	 */
	private void buildJsonData() {
		final String COMMA = ",";
		StringBuilder json = new StringBuilder();
		//start build
		json.append("{");
		insertJSON(json, KEY_CNONCE, this.clientNonce);
		json.append(COMMA);
		insertJSON(json, KEY_TIME_STAMP, this.timeStamp);
		json.append(COMMA);
		insertJSON(json, KEY_CLIENT_ID, this.clientId);
		json.append(COMMA);
		insertJSON(json, KEY_USER_ID, this.userId);
		//end build
		json.append("}");
		this.data = json.toString();		
	}

	/** 
	 * Helper for building JSON objects
	 * appends a key value pair to JSON data
	 * @param json json string builder
	 * @param key data key
	 * @param value data value
	 */
	private static void insertJSON(StringBuilder json, String key, String value) {
		final String QUOTE = "\"";
		final String SEPARATE = ":";
		
		//key:
		json.append(QUOTE);
		json.append(key);
		json.append(QUOTE);
		//deliminate
		json.append(SEPARATE);
		//value:
		json.append(QUOTE);
		json.append(value);
		json.append(QUOTE);
	}

	/**
	 * Gets time stamp for this instant
	 */
	private void obtainTimeStamp() {
		this.timeStamp = ZonedDateTime.now().format( DateTimeFormatter.ISO_INSTANT ).toString();
	}

	/**
	 * converts bytes to hex string
	 * @param bytes input bytes
	 * 
	 * @return corresponding hex string
	 */
	private static String toHexString(byte[] bytes) {
		Formatter formatter = new Formatter();
		
		for (byte b : bytes) {
			formatter.format("%02x", b);
		}

		return formatter.toString();
	}
	/**
	 * Converts a string to a byte array
	 * @param s The string to convert
	 * 
	 * @return byte representation of this string
	 */
	private static byte[] toByteArray(String s) {
		return s.getBytes();
	}

	/**
	 * Calculates HMAC256
 	 *
	 * @return hex string 
	 */
	public void computeHMAC()
		throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA256_ALGORITHM);
		Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
		mac.init(signingKey);
		this.encryptedBytes = mac.doFinal(data.getBytes());		
		this.encryptedData= toHexString(this.encryptedBytes);
	}

	/**
	 * @return time stamp of when data was encoded
	 */
	public String getTimeStamp() {
		return this.timeStamp;
	}
	/**
	 * @return data encoded as a string in JSON format
	 */
	public String getData() {
		return this.data;
	}

	/*
		FOR TESTING ONLY:
	*/

	// for debugging:
        private static final String STARS = "**************************************";
	private static final String DEBUG_STARS = "***";
	private static final String SUCCESS = " <success> ";
	private static final String FAILIURE = " <failiure> ";
	//vars for testing
	private static final String KEY="1c26e775-bb63-442c-9c45-b8764964dbbd";
        private static final String FAKE_KEY="1c26e775-bb63-442c-9c45-b8764964dbbc";
        private static final String CLIENT_ID = "<clientId>";
        private static final String USER_ID = "<userId>";

	/**
         * Prints a line of stars
         * Used for debugging outputs
         */
        public static void printStars() {
                println(STARS);
        }
	
	/**
         * Prints a string with multiples of 3 stars prefixed 
         * Used for debugging
         * @param n Number of stars x 3
         * @param s string to output
         */
        public static void println(int n, String s) {
                for(int i = 0; i < n; i ++) {
                        System.out.print(DEBUG_STARS);
                }
                println(s);
        }

        /**
         * Base method for printing
         * @param s string to print
         */
        public static void println(String s) {
                System.out.println(s);
        }

	private void useFakeKey() {
		this.key = FAKE_KEY;
	}

	public static void main(String[] args) throws Exception {
		// example of how to use
		example();
	}
	
	
	private static void example() {
		
		
		// 1. create object: pass in secret key, clientId, userId
		SignUtil myTest = new SignUtil(KEY, CLIENT_ID, USER_ID);
		// 2. initialize object: internally obtains a time stamp and builds JSON data
		myTest.init();
		try {
			// 3. encode data
			myTest.computeHMAC();

			// 4. verify
			// a. with good key
			boolean isGood = myTest.verify();
			String s = verifyResult(isGood);
			printStars();
			println(" Verification with correct key : " + s);
			// b. with bad key
			myTest.useFakeKey();
			isGood = myTest.verify();
			s = verifyResult(isGood);
			printStars();
			println(" Verification with false key : " + s);
		} catch(Exception xcpt) {
			xcpt.getMessage();
			xcpt.printStackTrace();
		}	
	}

	private static String verifyResult(boolean isGood) {
		return (isGood)?SUCCESS:FAILIURE;
	}

} //end class SignTest
