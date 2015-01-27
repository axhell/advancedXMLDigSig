package xmlsigmodule;

import java.security.PrivateKey;
import java.security.PublicKey;

import xmlsigcore.*;

public class InputValidationModule extends TestDigSig{

	
/**
 * This method is used to verify integrity of Certification Model Template, 
 * validate the identity of the signer and identity of the entity that require authorization to 
 * to create/edit Certification Model instance with his own Public key.
 * 
 * @param cmTsignature , signature of Certification Model template
 * @param pubkcmT	,	URI Public Key for Certification Model validation
 * @param pubkFW	,	URI Public Key of Framework that must be certified
 * @return
 * @throws Exception 
 */
	public static boolean RequestCMInstanceCreation(String cmTsignature, String pubkCMt, 
													String pubkFW) throws Exception {
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
	
	
	public static boolean RequestSignCMInstance(String cmTsignature, String pubkCMt, 
												String cmIunsigned, String pubkFW, 
												String privkFW) throws Exception{
		boolean sigprocess = false;
		final PublicKey pubKeyCMt = RSAPublicKeyReader.getPubKeyFormFile(pubkCMt);
		String cmTsig = cmTsignature;
		final PrivateKey privKFW = RSAPrivateKeyReader.getPrivKeyFromFile(privkFW);
		final PublicKey pubKeyFW = RSAPublicKeyReader.getPubKeyFormFile(pubkFW);
		String target = cmIunsigned;
		
		//Validate signature of Certification Model template
		ValidateSignature cmtemplate = new ValidateSignature(pubKeyCMt, target);
		
		if(cmtemplate.Validate()){
			sigprocess = true;
			GenDetached cminstance = new GenDetached(pubKeyFW, privKFW, target);
		}else{
			sigprocess = false;
		}
		
		
		return sigprocess;
		
	}


}
