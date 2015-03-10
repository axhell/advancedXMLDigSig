package xmlsigcore;
//import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import xmlsigcore.*;

/**
 * this class is used for test purposes only
 * @author axhell
 *
 */
public class TestDigSig {

	/**
	 * 
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		// 
		
		PublicKey pubKey = null;
		PrivateKey privKey = null;
		String target = null;
		
		if (args.length == 1 && args[0].equalsIgnoreCase("-CMinsSign")){
			
			//GenDetached inputs = new GenDetached(pubKey, privKey, target);
			//inputs.GenerateSig();
			
		}else if (args.length == 3 && args[0].equalsIgnoreCase("-v")){
			pubKey = RSAPublicKeyReader.getPubKeyFormFile(args[1]);
			target = args[2];
			ValidateSignature input = new ValidateSignature(pubKey, target);
			input.Validate();
		
		}else
			PrintUsage();
		
		

	}

	private static void PrintUsage() {
		// TODO Auto-generated method stub
		
		System.out.println("usage: TestDigSig [COMMAND]");
		System.out.println("option: ");
		System.out.println("-CMinsSign : generate signature for Certification Model instace");
		System.out.println("-CMinstVerify : verify signature one Certification Model instace");
	}

}
