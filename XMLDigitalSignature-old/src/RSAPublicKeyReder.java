import java.io.*;
import java.security.*;
import java.security.spec.*;

public class RSAPublicKeyReder {
	/**
	 * 
	 * @param filename, public key must be in DER format
	 * @return
	 * @throws Exception
	 */
	public static PublicKey get(String filename) throws Exception{
		
		File f = new File(filename);
		FileInputStream fis = new FileInputStream(f);
		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int)f.length()];
		dis.readFully(keyBytes);
		dis.close();
		
		//X509 Encoding
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		//Generate public key
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

}
