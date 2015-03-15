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







import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import xades4j.production.XadesFormatExtenderProfile;
import xades4j.production.XadesSignatureFormatExtender;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.utils.FileSystemDirectoryCertStore;
import xades4j.verification.SignatureSpecificVerificationOptions;
import xades4j.verification.XAdESForm;
import xades4j.verification.XAdESVerificationResult;
import xades4j.verification.XadesVerificationProfile;
import xades4j.verification.XadesVerifier;

public class XMLSignatureVerifyModule {
	/**
	 * Trust Anchors data
	 */
	private static final String truststore = "cert/truststore.jks";
	private static final String passwd = "password";
	
	Element signature;
	String baseuri;
	X509CertificateValidation cv;
	XAdESSignatureVerifier sv;
	
	public XMLSignatureVerifyModule(Document signature, String baseuri) throws Exception {
		
		
		this.signature = (Element)signature.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATURE).item(0);
		
		//KeyInfo ki;
		//ki.this.signature.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_KEYINFO);
		//X509Data xdata = new X509Data();
		//X509CertSelector certSelector = new X509CertSelector();
		//certSelector = 
		
		
		XadesVerificationProfile p = buildVerProfile();
		XadesVerifier v = p.newVerifier();
		SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().useBaseUri(this.baseuri);
		XAdESVerificationResult r = v.verify(this.signature, options);
		
		System.out.println("Verify the signer's certificate: ");
		X509CertificateValidation xv = new X509CertificateValidation(r.getValidationCertificate());
		xv.Validate(xv.cert);
		
		System.out.println(r.getSignatureForm());
		System.out.println(r.getSignatureAlgorithmUri());
		System.out.println(r.getSignedDataObjects().size());
		System.out.println(r.getQualifyingProperties().all().size());
	
	}
	public static void VerifyCMinsSignature() {
		// TODO Auto-generated method stub
		
	}

	public static XadesVerificationProfile buildVerProfile(){
		FileSystemDirectoryCertStore certStore = null;
		try {
			certStore = new FileSystemDirectoryCertStore("cert/CA/");
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
		
		char[] password = passwd.toCharArray();
		try {
			trustAnchors.load(new FileInputStream(truststore), password);
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
		//certStore.getStore().getCertificates().
		//trustAnchors.getCertificate("rootCA");
		XadesVerificationProfile p = new XadesVerificationProfile(certValidator);
		 return p;
	}
}
