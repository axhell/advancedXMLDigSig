package xmlsigmodule;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
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
import xades4j.verification.SignatureSpecificVerificationOptions;
import xades4j.verification.XAdESVerificationResult;
import xades4j.verification.XadesVerificationProfile;
import xades4j.verification.XadesVerifier;

public class XAdESSignatureValidationModule {
	
	/** Trust store in JKS format for trust anchor, intermediate and end-entity
	 *  certificate chain data */
	private static final String TRUSTSTORE = "cert/truststore.jks";
	private static final String PASSWD = "password";
	
	/** Certificate and CRLs store directory */
	private static final String CERTSTORE = "cert/CA/";
	
	Element signature;
	String baseuri;
	X509Certificate TA;
	/**
	 * Class constructor.
	 * @param signature document
	 * @param cert Trust anchor certificate
	 * @param baseuri absolute URI of the references resource 
	 * @throws Exception Cannot find Signature element
	 */
	public XAdESSignatureValidationModule(Document signature, X509Certificate cert, String baseuri) throws Exception {
		
		this.signature = getSignatureElement(signature);
		this.baseuri = baseuri;
		this.TA = cert;
	}
	/**
	 * Validation process: certificate constraints validation, 
	 * signature constraints validation
	 * and cryptographic verification.
	 * @return true if all validation process return true, false otherwise.
	 * @throws XAdES4jException CertificateValidationException, 
	 * 		   InvalidFormExtensionException,UnsupportedAlgorithmException,
	 *     	   InvalidSignatureException,XadesProfileResolutionException
	 *    	   ValidationDataException,XAdES4jXMLSigException.     
	 */
	public boolean validate() throws XAdES4jException {
		boolean isValid = false;
		
		XadesVerificationProfile p = buildVerProfile();
		
		XadesVerifier v = p.newVerifier();
		
		SignatureSpecificVerificationOptions options = 
				new SignatureSpecificVerificationOptions()
				.useBaseUri(this.baseuri);
		
		XAdESVerificationResult r = v.verify(this.signature, options);

		System.out.println();
		X509CertificateValidation xv = 
				new X509CertificateValidation(r.getValidationCertificate());
		if (xv.Validate(this.TA)) isValid = true;
		else isValid = false;
		
		System.out.println();
		XAdESSignatureValidation sv = new XAdESSignatureValidation(r);
        if (sv.ValSigVerifyForm()) isValid = true;
		else isValid = false;
        
        return isValid;
		
		
	}
	
	
	
	/**
	 * Extract Signature subtree.
	 * @param signature
	 * @return
	 * @throws Exception Cannot find Signature element
	 */
	private Element getSignatureElement(Document signature) throws Exception{
         
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
	/**
	 * This method build a profile for signature verification.
	 * @return a verification profile
	 */
	private static XadesVerificationProfile buildVerProfile(){
		FileSystemDirectoryCertStore certStore = null;
		try {
			/** Creates a CertStore from the contents of a file-system directory.
			 *  The directories are recursively searched for
			 *   X509 certificates or CRLs files  */
			certStore = new FileSystemDirectoryCertStore(CERTSTORE);
		} catch (CertificateException e2) {
			e2.printStackTrace();
		} catch (CRLException e2) {
			e2.printStackTrace();
		}
		KeyStore trustAnchors = null;
		try {
			/** Load the KeyStore */
			trustAnchors = KeyStore.getInstance(KeyStore.getDefaultType());
		} catch (KeyStoreException e1) {
			e1.printStackTrace();
		}
		
		char[] password = PASSWD.toCharArray();
		
		try {
			trustAnchors.load(new FileInputStream(TRUSTSTORE), password);
		} catch (NoSuchAlgorithmException | CertificateException
				| IOException e1) {
			e1.printStackTrace();
		}
		
		CertificateValidationProvider certValidator = null;
		
		try {
			/** Implementation of CertificateValidationProvider using a PKIX CertPathBuilder */
			certValidator = new PKIXCertificateValidationProvider(trustAnchors, false, certStore.getStore());
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
		}
	
		XadesVerificationProfile p = new XadesVerificationProfile(certValidator);
		 return p;
	}
	
}
