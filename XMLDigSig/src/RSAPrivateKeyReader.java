import java.io.*;
import java.security.*;
import java.security.spec.*;

public class RSAPrivateKeyReader {
	/**
	 *Return a {@link java.security.PrivateKey PrivateKey} from a {@link java.io.FileInputStream FileInputStream} encoded according to the standard format PKCS#8 
	 * using the {@link java.security.spec.PKCS8EncodedKeySpec#PKCS8EncodedKeySpec(byte[]) PKCS8EncodedKeySpec(byte[])}.
	 * @param filename , the private key in input <b>MUST</b> be encoded according to PKCS#8 standard.
	 * @return {@link java.security.PrivateKey PrivateKey}
	 * @throws Exception InvalidKeyFormat
	 */
	public static PrivateKey getPrivKeyFromFile(String filename) throws Exception {
		
		File f = new File(filename);
		/*debug
		BufferedReader br = new BufferedReader(new FileReader(f));
		String line = null;
		System.out.println("(RSAPrivateKeyReader.class)Private key content befor encoding: ");
		while ((line = br.readLine()) != null){
			System.out.println(line);
		}
		debug end*/
		FileInputStream fis = null;
		byte[] keyBytes = null;
		KeyFactory kf = null;
		PKCS8EncodedKeySpec spec = null;
		PrivateKey privKey = null;
		
		
		try {
			fis = new FileInputStream(f);
			try {
				DataInputStream dis = new DataInputStream(fis);
				keyBytes = new byte[(int)f.length()];
				dis.readFully(keyBytes);
				dis.close();
				
				
				//PKCS8 encoding
				spec = new PKCS8EncodedKeySpec(keyBytes);
				//Generate the private key
				kf = KeyFactory.getInstance("RSA");
				
				try {
					privKey = kf.generatePrivate(spec);
				}catch (Exception e) { throw new Exception("Private Key file is not valid");}
			
			} catch (IOException e){ e.printStackTrace();}
		}finally { 
		    try {
		        
				if (fis != null) {
		            fis.close();
		        }        
		    } catch (IOException e) {
		        // handle exception
		    	e.printStackTrace();
		    }
		}
		
		
		return privKey;
	}
	
	/**
	 *Return a {@link java.security.PrivateKey PrivateKey} from a {@link java.io.FileInputStream FileInputStream} encoded according to the standard format PKCS#8 
	 * using the {@link java.security.spec.PKCS8EncodedKeySpec#PKCS8EncodedKeySpec(byte[]) PKCS8EncodedKeySpec(byte[])}.
	 * @param f , the private key in input <b>MUST</b> be encoded according to PKCS#8 standard.
	 * @return {@link java.security.PrivateKey PrivateKey}
	 * @throws Exception InvalidKeyFormat
	 */
	public static PrivateKey getPrivKeyFromFile(File f) throws Exception {
		
		//File f = new File(filename);
		//debug
		BufferedReader br = new BufferedReader(new FileReader(f));
		String line = null;
		System.out.println("(RSAPrivateKeyReader.class)Private key content befor encoding: ");
		while ((line = br.readLine()) != null){
			System.out.println(line);
		}
		//fine test
		FileInputStream fis = new FileInputStream(f);
		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int)f.length()];
		dis.readFully(keyBytes);
		dis.close();
		br.close();
		
		//PKCS8 encoding
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		//Generate the private key
		KeyFactory kf = KeyFactory.getInstance("RSA");
		
		return kf.generatePrivate(spec);
	}
	
	

}
