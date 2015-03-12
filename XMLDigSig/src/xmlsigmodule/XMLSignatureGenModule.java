package xmlsigmodule;

import java.io.*;
import java.net.URLEncoder;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.security.cert.CertificateEncodingException;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;





//import org.apache.xml.security.stax.ext.Transformer;
import org.w3c.dom.Document;

import xades4j.XAdES4jException;
import xades4j.algorithms.XPath2FilterTransform.XPath2Filter;
import xades4j.production.*;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.DataObjectFormatProperty;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.*;
import xades4j.utils.XadesProfileResolutionException;
import xmlsigcore.RSAPrivateKeyReader;


public class XMLSignatureGenModule {
	public static void GenCMinstSignature() throws IOException, CertificateEncodingException{
		
		X509CertificateValidation certCA = null;
		X509CertificateValidation certUser = null;
		BufferedReader br = null;
		InputStream inStream = null;
		String certCAfile = null;
		String certUserfile = null;
		
		
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
		
		
		
		XadesSigner signer = getSigner(certCA.cert, privKCA);
		
		String cmtpath = "file://C:/Users/axhell/Documents/Github/XMLDigitalSignature/XMLDigSig/CMtemp.xml";
		//cmtpath = URLEncoder.encode(cmtpath, "UTF-8"); 
		signXAdESBES(cmtpath, signer);
		
		
		//CM template verifica
		//System.out.println("Certification Model Template (URI): ");
		//Altri input?
		//System.out.println("Optional input(blank to skip): ");
		
		
		
		inStream.close();
		
		
		certCA.ValidateRootCA(certCA.cert);
		certUser.Validate(certCA.cert);
		
		
		//genara firma
		//Reference //CM insta, CM template, optional
		//Canonicali
		
		//Firma
		
	}

	private static void signXAdESBES(String string, XadesSigner signer) {
		
		DataObjectDesc cmtemp = new DataObjectReference(string)
		.withTransform(XPath2Filter.intersect("/"))
		.withDataObjectFormat(new DataObjectFormatProperty("application/xml"))//MimeTipe qualify
		;//timestamp qualify
		SignedDataObjects objs = new SignedDataObjects(cmtemp);
		
		// Create the Document that will hold the resulting XMLSignature
        DocumentBuilderFactory sigdbf = DocumentBuilderFactory.newInstance();
        sigdbf.setNamespaceAware(true); // must be set
        Document sigdoc = null;
        try {
			sigdoc = sigdbf.newDocumentBuilder().newDocument();
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
        
        try {
			XadesSignatureResult result = signer.sign(objs, sigdoc);
		} catch (XAdES4jException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        
        // output the resulting document
        OutputStream os2 = null;
        try {
			os2 = new FileOutputStream("CMTSignature");
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
        //os2 = System.out;

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
}
