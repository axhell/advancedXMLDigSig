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
		
		if (args.length == 4 && args[0].equalsIgnoreCase("-s")){
			pubKey = RSAPublicKeyReader.getPubKeyFormFile(args[1]);
			privKey = RSAPrivateKeyReader.getPrivKeyFromFile(args[2]);
			target = args[3];
			GenDetached inputs = new GenDetached(pubKey, privKey, target);
			inputs.GenerateSig();
			
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
		
		System.out.println("usage: TestDigSig [COMMAND] [INPUT]");
		System.out.println("option: ");
		System.out.println("-s <PublicKey file> <PrivarteKey file> <URI> : generate detached digital signature of the target URI");
		System.out.println("-v <PublicKey file> <URI> : validate digital signature in the target URI");
	}

}
