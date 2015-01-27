package xmlsigmodule;

import xmlsigcore;

public class InputValidationModule extends TestDigSig{

	/**
	 * @param args
	 */
	public static boolean AuthorizationCMInstanceCreation(String cmTsignature, String cmTpubk, String fwpubk) {
		//
		boolean procede = false;
		
		RSAPublicKeyReader.getPubKeyFormFile("ert");
		
		
		return procede;

	}

}
