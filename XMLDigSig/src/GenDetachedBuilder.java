
import javax.xml.crypto.dsig.*;

import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilter2ParameterSpec;
import javax.xml.crypto.dsig.spec.XPathType;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;

import java.security.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;

	/**
	 * This class generate a Detached XMLSignature using the JSR 105 API.
	 *
	 */
	public class GenDetachedBuilder {
		private PublicKey pubkfile;
		private PrivateKey privkfile;
		private String targetURI;
		
		/**
		 * This builder is a input collector used to generate a detached signature
		 * @param pub , public key file
		 * @param priv , private key file
		 * @param tar , target file to be signed
		 */
		public GenDetachedBuilder(PublicKey pub, PrivateKey priv, String tar){
			this.pubkfile = pub;
			this.privkfile = priv;
			this.targetURI = tar;
		}
		
		
		
		
		public void GenerateSig() throws Exception {
	    	
	    	
	    	
	    	PrivateKey privKey = this.privkfile;
	    	//debug for private key content
			System.out.println("Private key content: ");
			System.out.println(privKey);
			
			
	    	PublicKey pubKey = this.pubkfile;
			//Test for public key content
			System.out.println("Public key content: ");
			System.out.println(pubKey);
	    	
			//target file to be signed
			//this.targetURI
			//final X509Certificate cert = CertUtil.loadCertificate(new BufferedInputStream(new FileInputStream(args[0]))); 
			//final KeyPair kp = new KeyPair(cert.getPublicKey(), key.getPrivateKey());
			
			
			/*//JAXP parser
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			//namespace-aware
			dbf.setNamespaceAware(true);
			
			DocumentBuilder builder = dbf.newDocumentBuilder();
			
			//Parse the input file
			Document doc = builder.parse(target);*/ 
			//Create signature context

	        // DOM XMLSignatureFactory that will be used to
	        // generate the XMLSignature and marshal it to DOM.
	        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

	        // Create a Reference to an external URI that will be digested
	        // using the SHA1 digest algorithm
	        //URI note file:///~/advancedXMLDigSig/ 
	        List<XPathType> xpaths = new ArrayList<XPathType>();
	        xpaths.add(new XPathType("/*", XPathType.Filter.INTERSECT));
	        
	        Reference ref = fac.newReference
	  	          (this.targetURI, fac.newDigestMethod(DigestMethod.SHA1, null),
	  	                Collections.singletonList
	  	                  (fac.newTransform(Transform.XPATH2, 
	  	                          new XPathFilter2ParameterSpec(xpaths))), null, null); 

	        List<Reference> ref2 = Collections.singletonList(fac.newReference
	          (this.targetURI, fac.newDigestMethod(DigestMethod.SHA1, null),
	                Collections.singletonList
	                  (fac.newTransform(Transform.XPATH2, 
	                          new XPathFilter2ParameterSpec(xpaths))), null, null)); 

	        /*<XPath Filter="intersect" xmlns="http://www.w3.org/2002/06/xmldsig-filter2">
      			//.
   			  </XPath>*/
	        	        
	        //Manifest with reference URI
	        Manifest manifest = fac.newManifest(ref2, "manifest-1");
	        
	        // Create the SignedInfo
	        SignedInfo si = fac.newSignedInfo(
	            fac.newCanonicalizationMethod
	                (CanonicalizationMethod.INCLUSIVE,
	                 (C14NMethodParameterSpec) null),
	            fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
	            Collections.singletonList(ref));

	        //throws XMLSecurityException
	      

	        // Create a KeyValue containing the RSA PublicKey that was generated
	        KeyInfoFactory kif = fac.getKeyInfoFactory();
	        KeyValue kv = kif.newKeyValue(pubKey);

	        // Create a KeyInfo and add the KeyValue to it
	        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));

	        // Create the XMLSignature (but don't sign it yet)
	        XMLSignature signature = fac.newXMLSignature(si, ki);

	        // Create the Document that will hold the resulting XMLSignature
	        DocumentBuilderFactory sigdbf = DocumentBuilderFactory.newInstance();
	        sigdbf.setNamespaceAware(true); // must be set
	        Document sigdoc = sigdbf.newDocumentBuilder().newDocument();

	        // Create a DOMSignContext and set the signing Key to the RSA
	        // PrivateKey and specify where the XMLSignature should be inserted
	        // in the target document (in this case, the document root)
	        DOMSignContext signContext = new DOMSignContext(privKey, sigdoc);

	        // Marshal, generate (and sign) the detached XMLSignature. The DOM
	        // Document will contain the XML Signature if this method returns
	        // successfully.
	        //signContext.setURIDereferencer(new MyURIDereferencer(ref));
	        signature.sign(signContext);

	        // output the resulting document
	        OutputStream os;
	        os = new FileOutputStream("." + File.separator + "Signature");
	
	        

	        TransformerFactory tf = TransformerFactory.newInstance();
	        Transformer trans = tf.newTransformer();
	        trans.transform(new DOMSource(sigdoc), new StreamResult(os));
	    }

	}

