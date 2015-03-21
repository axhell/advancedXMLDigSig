package xmlsigmodule;

import java.io.*;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.security.cert.CertificateEncodingException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;



















//import org.apache.xml.security.stax.ext.Transformer;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import xades4j.XAdES4jException;
import xades4j.algorithms.XPath2FilterTransform.XPath2Filter;
import xades4j.production.*;
import xades4j.properties.AllDataObjsCommitmentTypeProperty;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.DataObjectFormatProperty;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.*;
import xades4j.utils.XadesProfileResolutionException;
import xades4j.verification.XadesVerificationProfile;
import xades4j.xml.bind.xmldsig.XmlCanonicalizationMethodType;
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
		certCA.ValidateRootCA(certCA.cert);
		System.out.println();
		System.out.println("User certificate validation:");
		certUser.Validate(certCA.cert);
		
		
		
		//create CM template signature for test only
		XadesSigner signerCMT = getSigner(certCA.cert, privKCA);
		//file:/C:/Users/axhell/Documents/Github/XMLDigitalSignature/XMLDigSig/CMtemp.xml";
		//genara firma
		GenXAdESSignature newSig = new GenXAdESSignature(cmtempfn , null, PATH);
		//Sign 
		newSig.signCMtempXAdESBES(signerCMT);
		
		//GenEnvXAdESSignature newEnveloped = new GenEnvXAdESSignature(cmtempfn);
		//newEnveloped.signCMtempXAdESBES(signerCMT);
		
		System.out.println();
		
			//XMLSignatureVerifyModule vv = new XMLSignatureVerifyModule(signature, PATH);
			//vv.validate();
		
		
		
		
		
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
		//newSigI.signCMtempXAdESBES(signerCMI);
		
		
		
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
}
