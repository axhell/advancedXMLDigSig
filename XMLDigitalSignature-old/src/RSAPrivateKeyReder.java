import java.io.*;
import java.security.*;
import java.security.spec.*;

public class RSAPrivateKeyReder {
	/**
	 * 
	 * @param filename, private key must be in PKCS#8 format
	 * @return
	 * @throws Exception
	 */
	public static PrivateKey getPriv(String filename) throws Exception {
		
		File f = new File(filename);
		FileInputStream fis = new FileInputStream(f);
		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int)f.length()];
		dis.readFully(keyBytes);
		dis.close();
		
		//Encoding using PKCS8
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		//Generate the private key
		KeyFactory kf = KeyFactory.getInstance("RSA");
		
		return kf.generatePrivate(spec);
	}
	
	

}
