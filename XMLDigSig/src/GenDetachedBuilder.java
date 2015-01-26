import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dom.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilter2ParameterSpec;
import javax.xml.crypto.dsig.spec.XPathType;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.net.URI;
import java.security.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
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
	    	
	    	
	    	//File filePrivK = G.privkfile;
	    	//PrivateKey privKey = RSAPrivateKeyReader.getPrivKeyFromFile(filePrivK);
	    	PrivateKey privKey = this.privkfile;
	    	//debug for private key content
			System.out.println("Private key content: ");
			System.out.println(privKey);
			
			//File filePubK = G.pubkfile;
	    	//PublicKey pubKey = RSAPublicKeyReader.getPubKeyFormFile(filePubK);
	    	PublicKey pubKey = this.pubkfile;
			//Test for public key content
			System.out.println("Public key content: ");
			System.out.println(pubKey);
	    	
			//target file to be signed
			
			
			
			/*//JAXP parser
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			//namespace-aware
			dbf.setNamespaceAware(true);
			
			DocumentBuilder builder = dbf.newDocumentBuilder();
			
			//Parse the input file
			Document doc = builder.parse(target);*/ 
			//Create signature context

	        // First, create a DOM XMLSignatureFactory that will be used to
	        // generate the XMLSignature and marshal it to DOM.
	        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

	        // Create a Reference to an external URI that will be digested
	        // using the SHA1 digest algorithm
	        //URI note file:///~/advancedXMLDigSig/ 
	        List<XPathType> xpaths = new ArrayList<XPathType>();
	        xpaths.add(new XPathType("/", XPathType.Filter.INTERSECT));

	        Reference ref = fac.newReference
	          (this.targetURI, fac.newDigestMethod(DigestMethod.SHA1, null),
	                Collections.singletonList
	                  (fac.newTransform(Transform.XPATH2, 
	                          new XPathFilter2ParameterSpec(xpaths))), null, null); 

	        /*<XPath Filter="intersect" xmlns="http://www.w3.org/2002/06/xmldsig-filter2">
      			//.
   			  </XPath>*/
	        	        
	        
	        // Create the SignedInfo
	        SignedInfo si = fac.newSignedInfo(
	            fac.newCanonicalizationMethod
	                (CanonicalizationMethod.XPATH2,
	                 (C14NMethodParameterSpec) null),
	            fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
	            Collections.singletonList(ref));

	      

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
	        signature.sign(signContext);

	        // output the resulting document
	        OutputStream os;
	        /*if (args.length > 0) {
	           os = new FileOutputStream(args[0]);
	        } else {*/
	           os = System.out;
	        //}

	        TransformerFactory tf = TransformerFactory.newInstance();
	        Transformer trans = tf.newTransformer();
	        trans.transform(new DOMSource(sigdoc), new StreamResult(os));
	    }

		public void setPubKey(String string) {
			// TODO Auto-generated method stub
			
		}
	}

