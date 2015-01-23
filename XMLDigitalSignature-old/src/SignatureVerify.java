import java.io.FileInputStream;
import java.security.PublicKey;
import java.util.Scanner;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import java.security.*;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.XMLSignature;//Importantissimo
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

//import com.sun.org.apache.xml.internal.security.signature.XMLSignature;


public class SignatureVerify {
	public static void main(String args[]) throws Exception{
		
		System.out.println("Public key URI(in DER format)");
		Scanner sc2 = new Scanner(System.in);
		String filename2 = sc2.nextLine();
		//Test for input
		System.out.println("URI input: "+filename2);
		//Encode public key x.509
		PublicKey pubKey = RSAPublicKeyReader.getPubKeyFormFile(filename2);
		
		//Test for public key content
		System.out.println("Public key content: ");
		System.out.println(pubKey);
		
		//XML file input
		System.out.println("XML document to be signed:");
		Scanner xmlFileSc = new Scanner(System.in);
		String xmlFileName = xmlFileSc.nextLine();
		
		//Instantiate the document that contain the signature
		//JAXP parser
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		//namespace-aware
		dbf.setNamespaceAware(true);
		
		//instance of the document builder		
		DocumentBuilder builder = dbf.newDocumentBuilder();
		//Parse the input file
		Document doc = builder.parse(new FileInputStream(xmlFileName));
		
		
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
		DOMValidateContext valContext = new DOMValidateContext(pubKey, nl.item(0)); 
		
		//XMLsignature object
		XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM"); 
		//Extract the signature into XMLsignature object(unmarshaling)
		XMLSignature signature = factory.unmarshalXMLSignature(valContext); 
		
		boolean coreValidity = signature.validate(valContext); 
		
		System.out.println("signature is: "+ coreValidity);
		
	}
}
