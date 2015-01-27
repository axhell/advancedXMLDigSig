package xmlsigmodule;

import java.security.PrivateKey;
import java.security.PublicKey;

import xmlsigcore.*;

public class InputValidationModule extends TestDigSig{

	
/**
 * 
 * @param cmTsignature , signature of Certification Model template
 * @param pubkcmT	,	Public Key for Certification Model validation
 * @param pubkFW	,	Public Key of Framework that must be certified
 * @return
 * @throws Exception 
 */
	public static boolean RequestCMInstanceCreation(String cmTsignature, String pubkCMt, String pubkFW) throws Exception {
		//
		boolean auth = false;
		PublicKey pubKeyCMt = null;
		PublicKey pubKeyFW = null;
		String target = null;
		
		pubKeyCMt = RSAPublicKeyReader.getPubKeyFormFile(pubkCMt);
		target = cmTsignature;
		ValidateSignature input = new ValidateSignature(pubKeyCMt, target);
		
		if(input.Validate()){
			auth = true;
		}else{
			auth = false;
		}
		
		
		
		return auth;
		

	}


}
