	import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dom.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.*;
import java.util.Collections;
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
		/*private String pubkfilename;
		private String privkfilename;
		private String xmlfilename;*/
		private File pubkfile;
		private File privkfile;
		private File targetfile;
		
		/**
		 * This builder is a input collector used to generate a detached signature
		 * @param pub , public key file
		 * @param priv , private key file
		 * @param tar , target file to be signed
		 */
		public GenDetachedBuilder(File pub, File priv, File tar){
			this.pubkfile = pub;
			this.privkfile = priv;
			this.targetfile = tar;
		}
		
		
		
		public void GenerateSig(GenDetachedBuilder G) throws Exception {
	    	
	    	
	    	File filePrivK = G.privkfile;
	    	PrivateKey privKey = RSAPrivateKeyReader.getPrivKeyFromFile(filePrivK);
			//debug for private key content
			System.out.println("Private key content: ");
			System.out.println(privKey);
			
			File filePubK = G.pubkfile;
	    	PublicKey pubKey = RSAPublicKeyReader.getPubKeyFormFile(filePubK);
			//Test for public key content
			System.out.println("Public key content: ");
			System.out.println(pubKey);
	    	
			//target file to be signed
			File target = G.targetfile;

	        // First, create a DOM XMLSignatureFactory that will be used to
	        // generate the XMLSignature and marshal it to DOM.
	        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

	        // Create a Reference to an external URI that will be digested
	        // using the SHA1 digest algorithm
	        Reference ref = fac.newReference("http://www.w3.org/TR/xml-stylesheet", fac.newDigestMethod(DigestMethod.SHA1, null));
	        //serve xpath2 filter
	        // Create the SignedInfo
	        SignedInfo si = fac.newSignedInfo(
	            fac.newCanonicalizationMethod
	                (CanonicalizationMethod.XPATH2,
	                 (C14NMethodParameterSpec) null),
	            fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
	            Collections.singletonList(ref));

	      

	        // Create a KeyValue containing the DSA PublicKey that was generated
	        KeyInfoFactory kif = fac.getKeyInfoFactory();
	        KeyValue kv = kif.newKeyValue(pubKey);

	        // Create a KeyInfo and add the KeyValue to it
	        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));

	        // Create the XMLSignature (but don't sign it yet)
	        XMLSignature signature = fac.newXMLSignature(si, ki);

	        // Create the Document that will hold the resulting XMLSignature
	        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	        dbf.setNamespaceAware(true); // must be set
	        Document doc = dbf.newDocumentBuilder().newDocument();

	        // Create a DOMSignContext and set the signing Key to the RSA
	        // PrivateKey and specify where the XMLSignature should be inserted
	        // in the target document (in this case, the document root)
	        DOMSignContext signContext = new DOMSignContext(privKey, doc);

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
	        trans.transform(new DOMSource(doc), new StreamResult(os));
	    }
	}

