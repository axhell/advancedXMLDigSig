package xmlsigmodule;

public class TestModule {

	/**
	 * input targetURI, publickey, privatekey
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		//
		
		if (args.length<3||args.length>3){System.out.println("usage: TestSigModule <targetURI><PubK><PrivK>");
		}else{
			XMLSignatureModule.FakeSignature(args[0], args[1], args[2]);
		}

	}

}
