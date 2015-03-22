package xmlsigmodule;

import java.io.*;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.security.cert.CertificateEncodingException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;



















import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;


//import org.apache.xml.security.stax.ext.Transformer;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import xades4j.production.*;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.*;
import xades4j.utils.XadesProfileResolutionException;
import xmlsigcore.RSAPrivateKeyReader;


public class CMInstanceSignatureGenModule {
	public static void GenCMinstSignature() throws Exception{
		final String PATH = "file:/C:/Users/axhell/Documents/Github/XMLDigitalSignature/XMLDigSig/";
		
		X509CertificateValidation certCA = null;
		X509CertificateValidation certUser = null;
		BufferedReader br = null;
		InputStream inStream = null;
		String certCAfile = null;
		String certUserfile = null;
		String cmtemppath = null;
		String cmtempfn = null;
		String cminstpath = null;
		String cmtsignature = null;

		
		
		//Definition of the Trust anchors, root CA certificate with pub key.
		System.out.println("Root CA's certificate in DER format: ");
		br = new BufferedReader(new InputStreamReader(System.in));
		try {
			certCAfile = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		inStream = null;
		try {
			inStream = new FileInputStream(certCAfile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		certCA = new X509CertificateValidation(inStream);
				
		
		
		
		//User certificate with pub key.
		System.out.println("User's certificate in DER format: ");
		br = new BufferedReader(new InputStreamReader(System.in));
		try {
			certUserfile = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		inStream = null;
		try {
			inStream = new FileInputStream(certUserfile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		certUser = new X509CertificateValidation(inStream);
		
		PrivateKey privKCA = null;
		try {
			privKCA = RSAPrivateKeyReader.getPrivKeyFromFile("cert/ca_rsa_priveKey.der");
		} catch (Exception e) {
			e.printStackTrace();
		}
		PrivateKey privKuser = null;
		try {
			privKuser = RSAPrivateKeyReader.getPrivKeyFromFile("cert/my_rsa_priveKey.der");
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		
		System.out.println("CM Template file's name: ");
		br = new BufferedReader(new InputStreamReader(System.in));
		try {
			cmtempfn = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		
		
		
		System.out.println("CM Template Signature file's name: ");
		br = new BufferedReader(new InputStreamReader(System.in));
		try {
			cmtsignature = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		Document signature = getDocument(cmtsignature);
		
		
		
		System.out.println("CM Instance file's name: ");
		br = new BufferedReader(new InputStreamReader(System.in));
		try {
			cminstpath = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		
		//CM template verifica
		
		inStream.close();
		
		System.out.println("Trust Anchor certificate validation:");
		boolean tacert = certCA.Validate(certCA.cert);
		System.out.println();
		System.out.println("User certificate validation:");
		boolean ucert = certUser.Validate(certCA.cert);
		
		System.out.println();
		System.out.println("Certification Model Template signature validation: ");
		//create CM template signature for test only
		XadesSigner signerCMT = getSigner(certCA.cert, privKCA);
		//genara firma
		GenXAdESSignature newSig = new GenXAdESSignature(cmtempfn , null, PATH);
		//Sign
		newSig.signCMtempXAdESBES(signerCMT);
		//writeSignedDocumentToFile(newSig.signCMtempXAdESBES(signerCMT));
		
		//GenEnvXAdESSignature newEnveloped = new GenEnvXAdESSignature(cmtempfn);
		//newEnveloped.signCMtempXAdESBES(signerCMT);
		
		System.out.println();
		
		//XAdESSignatureValidationModule vv = new XAdESSignatureValidationModule(signature , PATH);
		//boolean cmt = vv.validate();
		boolean cmt = false;
		
		
		
		
		
		
		
		if(tacert && ucert && cmt){
			
		
		/**
		 * Create a signer for the Certification Model Instance
		 */
		//XadesSigner signerCMI = getSigner(certUser.cert, privKuser);
		/**
		 * Generate the signature content
		 */
		//GenXAdESSignature newSigI = new GenXAdESSignature(cminstpath , PATH);
		/**
		 * Sign
		 */
		//writeSignedDocumentToFile(newSigI.signCMtempXAdESBES(signerCMI));
			System.out.println();
			System.out.println("Certification Model Instance signed correctly");
		}else{
			System.out.println();
			System.out.println("Error, Certification Model Instance not signed");
		}
		
	}

	
	       
	
	

	private static XadesSigner getSigner(X509Certificate cert,
			PrivateKey privK) {
		try {
			KeyingDataProvider kp = new DirectKeyingDataProvider(cert, privK);
			XadesSigningProfile p = new XadesBesSigningProfile(kp);
			return p.newSigner();
			} catch (XadesProfileResolutionException e) {
				e.printStackTrace();
			}
		return null;
		
		
	}
	
	/**
     * Load a Document from an XML file
     * @param path The path to the file
     * @return The document extracted from the file
	 * @throws ParserConfigurationException 
	 * @throws IOException 
	 * @throws SAXException 
	 * @throws FileNotFoundException 
     */
    private static Document getDocument(String filename) throws ParserConfigurationException, FileNotFoundException, SAXException, IOException {
       Document signature = null;
    	
    	DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);		
		DocumentBuilder builder = dbf.newDocumentBuilder();
		signature = builder.parse(new FileInputStream(filename));
		
		return signature;
    }
    //BUG
    private static void writeSignedDocumentToFile(Document sigdoc) {
		OutputStream os2 = null;
        try {
			os2 = new FileOutputStream("CMISignature.xml");
		} catch (FileNotFoundException e1) {
		
			e1.printStackTrace();
		}

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = null;
		try {
			trans = tf.newTransformer();
		} catch (TransformerConfigurationException e) {
			e.printStackTrace();
		}
        trans.setOutputProperty(OutputKeys.INDENT, "yes");
        try {
			trans.transform(new DOMSource(sigdoc), new StreamResult(os2));
		} catch (TransformerException e) {
			e.printStackTrace();
		}
		
    }
}
