package xmlsigcore;
import java.io.FileInputStream;
import java.security.PublicKey;

import javax.xml.crypto.dsig.XMLSignature;

import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;


import org.w3c.dom.Document;
import org.w3c.dom.NodeList;


public class ValidateSignature {
	
	private PublicKey pubkfile;
	private String targetURI;
	
	/**
	 * This builder is a input collector used to generate a detached signature
	 * @param pub , public key file
	 * @param tar , target file to be signed
	 */
	public ValidateSignature(PublicKey pub, String tar){
		this.pubkfile = pub;
		this.targetURI = tar;
	}
	
	public boolean Validate() throws Exception{
	//Instantiate the document that contain the signature
	//JAXP parser
	DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	//namespace-aware
	dbf.setNamespaceAware(true);
	
	//instance of the document builder		
	DocumentBuilder builder = dbf.newDocumentBuilder();
	//Parse the input file
	Document doc = builder.parse(new FileInputStream(this.targetURI));
	
	
	/*Specifying the Signature Element to be Validated
	We need to specify the Signature element that we want to validate, 
	since there could be more than one in the document. 
	We use the DOM method Document.getElementsByTagNameNS, 
	passing it the XML Signature namespace URI and the tag name of the Signature element, 
	as shown:*/

	NodeList nl = doc.getElementsByTagNameNS
	  (XMLSignature.XMLNS, "Signature");
	if (nl.getLength() == 0) {
	  throw new Exception("Cannot find Signature element");
	} 

	/*//Check which element that is not empty
	 //KeyValueKeySelector extended keyselector class approfondire
	for(int i = 0; i<= nl.getLength();i++){
		if (nl != null){ 
			DOMValidateContext valContext = new DOMValidateContext(new KeyValueKeySelector(), nl.item(i));
		}
	}*/
	//In this early version i'll set the public key manually 
	DOMValidateContext valContext = new DOMValidateContext(this.pubkfile, nl.item(0)); 
	
	//XMLsignature object
	XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM"); 
	//Extract the signature into XMLsignature object(unmarshaling)
	XMLSignature signature = factory.unmarshalXMLSignature(valContext); 
	
	boolean coreValidity = signature.validate(valContext); 
	
	System.out.println("signature is: "+ coreValidity);
	return coreValidity;
	
	}
}
