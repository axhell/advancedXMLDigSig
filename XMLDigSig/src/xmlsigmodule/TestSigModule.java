package xmlsigmodule;

public class TestSigModule {

	/**
	 * input targetURI, publickey, privatekey
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		//
		XMLSignatureModule.FakeSignature(args[0], args[1], args[2]);

	}

}
