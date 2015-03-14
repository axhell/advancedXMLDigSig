package xmlsigmodule;

import java.io.*;
import java.net.URLEncoder;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.security.cert.CertificateEncodingException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;














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
	public static void GenCMinstSignature() throws IOException, CertificateEncodingException, ParserConfigurationException{
		
		X509CertificateValidation certCA = null;
		X509CertificateValidation certUser = null;
		BufferedReader br = null;
		InputStream inStream = null;
		String certCAfile = null;
		String certUserfile = null;
		String cmtemppath = null;
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
		
		PrivateKey privKuser = null;
		try {
			privKuser = RSAPrivateKeyReader.getPrivKeyFromFile("cert/ca_rsa_priveKey.der");
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		
		
		
		System.out.println("CM Template absolute path (URI): ");
		br = new BufferedReader(new InputStreamReader(System.in));
		try {
			cmtemppath = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		System.out.println("CM Template Signature relative path (URI): ");
		br = new BufferedReader(new InputStreamReader(System.in));
		try {
			cmtsignature = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);		
		DocumentBuilder builder = dbf.newDocumentBuilder();
		Document signature = null;
		try {
			signature = builder.parse(new FileInputStream(cmtsignature));
		} catch (SAXException e1) {
			e1.printStackTrace();
		}
	
		System.out.println("CM Instance absolute path (URI): ");
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
		
		
		/*
		//create CM template signature for test only
		XadesSigner signerCMT = getSigner(certCA.cert, privKuser);
		//file://C:/Users/axhell/Documents/Github/XMLDigitalSignature/XMLDigSig/CMtemp.xml";
		//genara firma
		GenXAdESSignature newSig = new GenXAdESSignature(cmtemppath , null);
		//Sign 
		newSig.signCMtempXAdESBES(signerCMT);
		*/
		
		System.out.println();
		try {
			XMLSignatureVerifyModule vv = new XMLSignatureVerifyModule(signature, cmtemppath);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		
		
		/**
		 * Create a signer for the Certification Model Instance
		 */
		//XadesSigner signerCMI = getSigner(certUser.cert, privKuser);
		/**
		 * Generate the signature content
		 */
		//GenXAdESSignature newSigI = new GenXAdESSignature(cminstpath , cmtemppath);
		/**
		 * Sign
		 */
		//newSigI.signCMtempXAdESBES(signerCMI);
		
		
		
	}

	
	       
	
	

	private static XadesSigner getSigner(X509Certificate cert,
			PrivateKey privKCA) {
		try {
			KeyingDataProvider kp = new DirectKeyingDataProvider(cert, privKCA);
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
     */
    private static Document getDocument(String path) {
        try {
            // Load the XML to append the signature to.
            File fXmlFile = new File(path);
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(fXmlFile);
     
            return doc;
        } catch (SAXException ex) {
            return null;
        } catch (IOException ex) {
            return null;
        } catch (ParserConfigurationException ex) {
            return null;
        }
    }
}
