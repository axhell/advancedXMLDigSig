package xmlsigcore;
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
		PublicKey pubKey = null;
		File f = new File(filename);
		FileInputStream fis = null;
		byte[] keyBytes = null;
		KeyFactory kf = null;
		X509EncodedKeySpec spec = null;
		
		try {
			fis = new FileInputStream(f);
			
			try {
				DataInputStream dis = new DataInputStream(fis);
				keyBytes = new byte[(int)f.length()];
				dis.readFully(keyBytes);
				try {
			        
					if (dis != null) {
			            dis.close();
					}
			    } catch (IOException e) {
				        // handle exception
				    	e.printStackTrace();}
				
				spec = new X509EncodedKeySpec(keyBytes);
				//Generate public key
				kf = KeyFactory.getInstance("RSA");
				
				try {
					pubKey = kf.generatePublic(spec);
				} catch (Exception e) { throw new Exception("Public Key format is not valid");}
				
			} catch (IOException e) {e.printStackTrace();   } 
			
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
		
		return pubKey;
				
	}
	
	/**
	 **Return a {@link java.security.PublicKey PublicKey} from a {@link java.io.FileInputStream FileInputStream} encoded according to the X.509 standard, 
	 * using the {@link java.security.spec.X509EncodedKeySpec#X509EncodedKeySpec(byte[] encodedKey) X509EncodedKeySpec(byte[] encodedKey)}.
	 * @param filename , the public key in input <b>must</b> be encoded according to the X.509 standard.
	 * @return {@link java.security.PublicKey PublicKey}
	 * @throws FileNotFoundException 
	 * @throws Exception InvalidKeyFormat
	 */
	public static PublicKey getPubKeyFormFile(File f) throws FileNotFoundException {
		
		PublicKey pubKey = null;
	
		FileInputStream fis = null;
		byte[] keyBytes = null;
		KeyFactory kf = null;
		X509EncodedKeySpec spec = null;
		try {
			fis = new FileInputStream(f);
			
			try {
				DataInputStream dis = new DataInputStream(fis);
				keyBytes = new byte[(int)f.length()];
				dis.readFully(keyBytes);
				try {
			        
					if (dis != null) {
			            dis.close();
					}
			    } catch (IOException e) {
				        // handle exception
				    	e.printStackTrace();}
				
				spec = new X509EncodedKeySpec(keyBytes);
				//Generate public key
				kf = KeyFactory.getInstance("RSA");
				
				try {
					pubKey = kf.generatePublic(spec);
				} catch (Exception e) { throw new Exception("Couldn't fide a valid Public Key ");}
				
			} catch (Exception e) {e.printStackTrace();   } 
			
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
		
		return pubKey;
	}


}
