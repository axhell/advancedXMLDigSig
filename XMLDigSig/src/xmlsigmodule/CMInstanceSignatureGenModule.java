package xmlsigmodule;

import java.io.*;
import java.net.URLEncoder;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.security.cert.CertificateEncodingException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;









//import org.apache.xml.security.stax.ext.Transformer;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import xades4j.XAdES4jException;
import xades4j.algorithms.XPath2FilterTransform.XPath2Filter;
import xades4j.production.*;
import xades4j.properties.AllDataObjsCommitmentTypeProperty;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.DataObjectFormatProperty;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.*;
import xades4j.utils.XadesProfileResolutionException;
import xades4j.xml.bind.xmldsig.XmlCanonicalizationMethodType;
import xmlsigcore.RSAPrivateKeyReader;


public class CMInstanceSignatureGenModule {
	public static void GenCMinstSignature() throws IOException, CertificateEncodingException{
		
		X509CertificateValidation certCA = null;
		X509CertificateValidation certUser = null;
		BufferedReader br = null;
		InputStream inStream = null;
		String certCAfile = null;
		String certUserfile = null;
		String cmtemppath = null;
		String cminstpath = null;

		
		
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
			privKuser = RSAPrivateKeyReader.getPrivKeyFromFile("cert/my_rsa_priveKey.der");
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
		
		
		System.out.println("CM Instance absolute path (URI): ");
		br = new BufferedReader(new InputStreamReader(System.in));
		try {
			cminstpath = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		
		//CM template verifica
		
		
		
		
		inStream.close();
		
		
		certCA.ValidateRootCA(certCA.cert);
		certUser.Validate(certCA.cert);
		
		
		
		//Reference //CM insta, CM template, optional
		XadesSigner signer = getSigner(certUser.cert, privKuser);
		//file://C:/Users/axhell/Documents/Github/XMLDigitalSignature/XMLDigSig/CMtemp.xml";
		//genara firma
		GenXAdESSignature newSig = new GenXAdESSignature(cminstpath, cmtemppath);
		//Sign 
		newSig.signCMiXAdESBES(signer);
		
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
            doc.getDocumentElement().normalize();
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
