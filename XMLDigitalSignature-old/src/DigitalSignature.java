import java.io.*;
import java.security.*;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.*;
import javax.xml.crypto.dom.*;
import javax.xml.crypto.dsig.dom.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

import java.io.*;
import java.util.*;

class DigitalSignature {
	
	public static void main(String[] args) throws Exception{
		
		
		//Get private Key(RSA)
		System.out.println("private key URI(in PKCS8 format):");
		//Scanner sc = new Scanner(System.in);
		//String filename = sc.nextLine();
		//Test for input
		String filename = "/media/windows/Users/axhell/Google Drive/Dropbox/TESI/javaXMLDigSig/private_key.der";
		System.out.println("URI input: "+filename);
		//Encode private key
		PrivateKey privKey = RSAPrivateKeyReader.getPrivKeyFromFile(filename);
		
		//Test for private key content
		System.out.println("Private key content: ");
		System.out.println(privKey);
		
		System.out.println("Public key URI(in DER format)");
		//Scanner sc2 = new Scanner(System.in);
		//String filename2 = sc2.nextLine();
		//Test for input
		String filename2 = "/media/windows/Users/axhell/Google Drive/Dropbox/TESI/javaXMLDigSig/public_key.der";
		System.out.println("URI input: "+filename2);
		//Encode public key x.509
		PublicKey pubKey = RSAPublicKeyReader.getPubKeyFormFile(filename2);
		
		//Test for public key content
		System.out.println("Public key content: ");
		System.out.println(pubKey);
		
		
		/*
		//DOM XMLSIgnatureFactory
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
		
		//URI reference, using SHA1 digest
		Reference ref = fac.newReference("prova.xml", fac.newDigestMethod(DigestMethod.SHA256,  null));
		*/
		
		//XML file input
		System.out.println("XML document to be signed:");
		//Scanner xmlFileSc = new Scanner(System.in);
		//String xmlFileName = xmlFileSc.nextLine();
		String xmlFileName ="/media/windows/Users/axhell/Google Drive/Dropbox/TESI/javaXMLDigSig/example.xml";
		
		//JAXP parser
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		//namespace-aware
		dbf.setNamespaceAware(true);
		
		DocumentBuilder builder = dbf.newDocumentBuilder();
		
		//Parse the input file
		Document doc = builder.parse(new FileInputStream(xmlFileName)); 
		//Create signature context
		DOMSignContext dsc = new DOMSignContext(privKey, doc.getDocumentElement()); 
		//Assembling the XML signature
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM"); 
		//"" URI of the object to be signed, set the digest method, 
		//apply a transform to the document to allow the enveloped content
		Reference ref = fac.newReference
				  ("", fac.newDigestMethod(DigestMethod.SHA1, null),
				  Collections.singletonList(fac.newTransform(Transform.ENVELOPED,
				  (TransformParameterSpec) null)), null, null); 
		
		Reference ref2 = fac.newReference("/media/windows/Users/axhell/Google Drive/Dropbox/TESI/javaXMLDigSig/risorsa1.xml", fac.newDigestMethod(DigestMethod.SHA1, null));
		List<Reference> references = new ArrayList<Reference>();
		references.add(ref);
		references.add(ref2);
		
		
		//Create the signedinfo object
		//
		SignedInfo si = fac.newSignedInfo
				  (fac.newCanonicalizationMethod
				    (CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
				      (C14NMethodParameterSpec) null),
				    fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
				    Collections.singletonList(ref)); 
	
		//Create the KeyInfo object
		KeyInfoFactory kif = fac.getKeyInfoFactory();
		//Get key value from keyinfofactory
		KeyValue kv = kif.newKeyValue(pubKey);
		KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));
		
		//Create the signature object
		XMLSignature signature = fac.newXMLSignature(si, ki);
		
		//Sign 
		signature.sign(dsc);
		
		//Print result
		OutputStream os;
		if (xmlFileName.length() > 1) {
		  os = new FileOutputStream(xmlFileName+"signed");
		} else {
		  os = System.out;
		} 
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans = tf.newTransformer();
		trans.transform(new DOMSource(doc), new StreamResult(os)); 
		
		os.close();
		
	}
	

}
