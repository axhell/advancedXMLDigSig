package xmlsigmodule;

public class TestModule {

	/**
	 * input targetURI, publickey, privatekey
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		//
		
		if (args.length != 1){ PrintUsage();
		}else if(args[0].equalsIgnoreCase("-CMinsSign")){
			CMInstanceSignatureGenModule.GenCMinstSignature();
		}else if(args[0].equalsIgnoreCase("-CMinsVerify")){
			CMInstanceSignatureVerModule.VerifyCMinsSignature();
		}

	}
	private static void PrintUsage() {
		System.out.println("usage: TestDigSig [COMMAND]");
		System.out.println("option: ");
		System.out.println("-CMinsSign : generate signature for Certification Model instace");
		System.out.println("-CMinsVerify : verify signature one Certification Model instace");
	}

}
