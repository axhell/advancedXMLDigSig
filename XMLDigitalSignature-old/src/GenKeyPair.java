import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;



public class GenKeyPair {

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		
		//Create XMLSIgnatureFactory
		//XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
				
		//Create DSA pair Key
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
		
		//Create a Key value containing the DSA public that was generated
		//KeyInfoFactory kif = fac.get
		
		//Generate a secure random number used to initialize the key
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		
		//key initialization
		kpg.initialize(1024, random);
		
		//Generate key pair
		KeyPair kp = kpg.generateKeyPair();
		PrivateKey priv = kp.getPrivate();
		PublicKey pub = kp.getPublic();
		
		/*Store private key in a file*/
		byte[] keyr = priv.getEncoded();
		FileOutputStream keyrfos = new FileOutputStream("privkey");
		keyrfos.write(keyr);
		keyrfos.close();
		/*Store public key in a file*/
		byte[] key = pub.getEncoded();
		FileOutputStream keypfos = new FileOutputStream("pubkey");
		keypfos.write(key);
		keypfos.close();
	}

}
