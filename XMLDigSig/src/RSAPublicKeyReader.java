import java.io.*;
import java.security.*;
import java.security.spec.*;

public class RSAPublicKeyReader {
	/**
	 **Return a {@link java.security.PublicKey PublicKey} from a URI, encoded according to the X.509 standard, 
	 * using the {@link java.security.spec.X509EncodedKeySpec#X509EncodedKeySpec(byte[] encodedKey) X509EncodedKeySpec(byte[] encodedKey)}.
	 * @param filename , the public key in input <b>must</b> be encoded according to the X.509 standard.
	 * @return {@link java.security.PublicKey PublicKey}
	 * @throws Exception InvalidKeyFormat
	 */
	public static PublicKey getPubKeyFormFile(String filename) throws Exception{
		
		File f = new File(filename);
		FileInputStream fis = null;
		byte[] keyBytes = null;
		try {
			fis = new FileInputStream(f);
			
			try {
				DataInputStream dis = new DataInputStream(fis);
				keyBytes = new byte[(int)f.length()];
				dis.readFully(keyBytes);
				
			} catch (Exception e) { e.printStackTrace(); } 
			
		} catch (IOException e){
			// handle exception
			e.printStackTrace();
		} finally { 
		    try {
		        
				if (fis != null) {
		            fis.close();
		        }        
		    } catch (IOException e) {
		        // handle exception
		    	e.printStackTrace();
		    }
		}
		
		
		
		//X509 Encoding
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		//Generate public key
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
		

		
	}
	
	/**
	 **Return a {@link java.security.PublicKey PublicKey} from a {@link java.io.FileInputStream FileInputStream} encoded according to the X.509 standard, 
	 * using the {@link java.security.spec.X509EncodedKeySpec#X509EncodedKeySpec(byte[] encodedKey) X509EncodedKeySpec(byte[] encodedKey)}.
	 * @param filename , the public key in input <b>must</b> be encoded according to the X.509 standard.
	 * @return {@link java.security.PublicKey PublicKey}
	 * @throws Exception InvalidKeyFormat
	 */
	public static PublicKey getPubKeyFormFile(File f) throws Exception{
		
		//File f = new File(filename);
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
