package xmlsigmodule;

import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

import xmlsigcore.*;

public class XMLSignatureModule {

	
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
	
	/**
	 * Sign Certification Model instance in input, after validate the signature of Certification Model template in input, 
	 * and all key's certificate.
	 * @param cmTsignature , URI signature of CM template
	 * @param pubkCMt	, URI Public Key for Certification Model validation
	 * @param cmIunsigned , URI CM instance unsigned
	 * @param pubkFW	, URI Public Key of the framework used to sign CM instance
	 * @param privkFW	, URI Private Key of the framework used to sign CM instance
	 * @return
	 * @throws Exception
	 */
	public static boolean RequestSignCMInstance(String cmTsignature, String pubkCMt, 
												String cmIunsigned, String pubkFW, 
												String privkFW) throws Exception{
		boolean sigprocess = false;
		final PublicKey pubKeyCMt = RSAPublicKeyReader.getPubKeyFormFile(pubkCMt);
		String cmTsig = cmTsignature;
		final PrivateKey privKFW = RSAPrivateKeyReader.getPrivKeyFromFile(privkFW);
		final PublicKey pubKeyFW = RSAPublicKeyReader.getPubKeyFormFile(pubkFW);
		String target = cmIunsigned;
		
		// Create the Document that will hold the resulting XMLSignature
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		//namespace-aware
		dbf.setNamespaceAware(true);
		//instance of the document builder		
		DocumentBuilder builder = dbf.newDocumentBuilder();
		//Parse the input file
		Document sigdoc = null;
		
		//Validate signature of Certification Model template
		ValidateSignature cmtemplate = new ValidateSignature(pubKeyCMt, cmTsig);
		
		if(cmtemplate.Validate()){
			GenDetached cminstance = new GenDetached(pubKeyFW, privKFW, target);
			sigdoc = cminstance.GenerateSig();
			if (sigdoc != null){
				sigprocess = true;
				
				 OutputStream os;
			     os = System.out;
			     TransformerFactory tf = TransformerFactory.newInstance();
			     Transformer trans = tf.newTransformer();
			     trans.setOutputProperty(OutputKeys.INDENT, "yes");
			     trans.transform(new DOMSource(sigdoc), new StreamResult(os));
					
				
			}
			
		}else{
			sigprocess = false;
			System.out.println("Validation of CM template failed");
		}
		
		
		
		return sigprocess;
		
	}
	/**
	 * create an untrusted signature for test purposes
	 * @param targetURI
	 * @param pubkFW
	 * @param privkFW
	 * @return
	 * @throws Exception
	 */
	public static boolean FakeSignature(String targetURI, String pubkFW, String privkFW) throws Exception{
	
		boolean sigprocess = false;
		
		final PrivateKey privKFW = RSAPrivateKeyReader.getPrivKeyFromFile(privkFW);
		final PublicKey pubKeyFW = RSAPublicKeyReader.getPubKeyFormFile(pubkFW);
		String target = targetURI;
		
		// Create the Document that will hold the resulting XMLSignature
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		//namespace-aware
		dbf.setNamespaceAware(true);
		//instance of the document builder		
		//DocumentBuilder builder = dbf.newDocumentBuilder();
		//Parse the input file
		Document sigdoc = null;
		
		GenDetached cminstance = new GenDetached(pubKeyFW, privKFW, target);
		sigdoc = cminstance.GenerateSig();
		sigprocess = true;
		
		OutputStream os;
		os = System.out;
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans = tf.newTransformer();
		trans.setOutputProperty(OutputKeys.INDENT, "yes");
		trans.transform(new DOMSource(sigdoc), new StreamResult(os));



		return sigprocess;

	}
}
