import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PrivateKey;
import java.security.PublicKey;


public class TestDigSig {

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		
		PublicKey pubKey = null;
		PrivateKey privKey = null;
		String target = null;
		
		if (args[0] != null){
			pubKey = RSAPublicKeyReader.getPubKeyFormFile(args[0]);
		}else{
			System.out.println("Public Key input field MUST NOT be empty");
		}
		
		if (args[1] != null){
			privKey = RSAPrivateKeyReader.getPrivKeyFromFile(args[1]);
		}else{
			System.out.println("Private Key input field MUST NOT be empty");
		}
		
		if (args[2] != null){
			target = args[2];
		}else{
			System.out.println("Target of signature URI field MUST NOT be empty");
		}
		
		
		
		GenDetachedBuilder inputs = new GenDetachedBuilder(pubKey, privKey, target);
		
		inputs.GenerateSig();

	}

}
