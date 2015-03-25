package xmlsigmodule;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;

import javax.xml.crypto.dsig.XMLSignature;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import xades4j.XAdES4jException;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.utils.FileSystemDirectoryCertStore;
import xades4j.utils.XadesProfileResolutionException;
import xades4j.verification.SignatureSpecificVerificationOptions;
import xades4j.verification.XAdESVerificationResult;
import xades4j.verification.XadesVerificationProfile;
import xades4j.verification.XadesVerifier;

public class XAdESSignatureValidationModule {
	
	//Trust Anchors data
	private static final String TRUSTSTORE = "cert/truststore.jks";
	private static final String PASSWD = "password";
	
	//Certificate Store directory
	private static final String CERTSTORE = "cert/CA/";
	
	
	Element signature;
	String baseuri;
	X509Certificate TA;
	
	public XAdESSignatureValidationModule(Document signature, X509Certificate cert, String baseuri) throws Exception {
		
		
		//this.signature = (Element)signature.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATURE).item(0);
		this.signature = getSignatureElement(signature);
		this.baseuri = baseuri;
		this.TA = cert;
	}
	
	public boolean validate() throws XAdES4jException {
		boolean isValid = false;
		
		XadesVerificationProfile p = buildVerProfile();
		
		XadesVerifier v = p.newVerifier();
		
		SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().useBaseUri(this.baseuri);
		
		XAdESVerificationResult r = v.verify(this.signature, options);

		
		System.out.println();
		System.out.println("Verify the signer's certificate: ");
		X509CertificateValidation xv = new X509CertificateValidation(r.getValidationCertificate());
		if (xv.Validate(this.TA)) isValid = true;
		else isValid = false;
		
	
		System.out.println();
		System.out.println("Verify the signature form: ");
		XAdESSignatureVerifier sv = new XAdESSignatureVerifier(r);
        if (sv.ValSigVerifyForm()) isValid = true;
		else isValid = false;
        
        return isValid;
		
		
	}
	
	
	
	
	private Element getSignatureElement(Document signature) throws Exception{
         //final NodeList nList = signature.getElementsByTagName("ds:Signature");
         
         NodeList nList = signature.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        		if (nList.getLength() == 0) {
        		  throw new Exception("Cannot find Signature element");
        		} 
         
         Element elem = null;
         for (int temp = 0; temp < nList.getLength(); temp++) {
             final Node nNode = nList.item(temp);
             if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                 elem = (Element) nNode;
             }
         }
         elem.normalize();
         
         return elem;
	}
	/*
	public 
	final NodeList nList2 = doc.getElementsByTagName("ds:X509Certificate");
    final List<String> certDataList = new ArrayList<String>();
    for (int temp = 0; temp < nList2.getLength(); temp++) {
        final Node nNode = nList2.item(temp);
        certDataList.add(nNode.getTextContent());
    }
    certList = getCert(certDataList);
	*/
	private static XadesVerificationProfile buildVerProfile(){
		FileSystemDirectoryCertStore certStore = null;
		try {
			certStore = new FileSystemDirectoryCertStore(CERTSTORE);
		} catch (CertificateException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		} catch (CRLException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		KeyStore trustAnchors = null;
		try {
			trustAnchors = KeyStore.getInstance(KeyStore.getDefaultType());
		} catch (KeyStoreException e1) {
			e1.printStackTrace();
		}
		
		char[] password = PASSWD.toCharArray();
		try {
			trustAnchors.load(new FileInputStream(TRUSTSTORE), password);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		CertificateValidationProvider certValidator = null;
		try {
			certValidator = new PKIXCertificateValidationProvider(trustAnchors, false, certStore.getStore());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		XadesVerificationProfile p = new XadesVerificationProfile(certValidator);
		 return p;
	}
	
}
