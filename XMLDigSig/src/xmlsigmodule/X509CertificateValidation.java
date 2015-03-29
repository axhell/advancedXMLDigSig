package xmlsigmodule;

import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.util.Date;

import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

public class X509CertificateValidation {
	X509Certificate cert;
	/** Report of the validation process */
	private String[] report;
	
	/**
	 * Class constructor, import X509 certificate from file
	 * @param inStream file representing certificate to be signed
	 */
	X509CertificateValidation(InputStream inStream){
		CertificateFactory cf = null;
		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e1) {
			e1.printStackTrace();
		}
		try {
			this.cert = (X509Certificate)cf.generateCertificate(inStream);
		} catch (CertificateException e1) {
			e1.printStackTrace();
		}
		
		this.report = new String[10];
	}
	
	/**
	 * Class constructor
	 * @param cert certificate to be validated
	 */
	public X509CertificateValidation(X509Certificate cert) {
		this.cert = cert;
		this.report = new String[10];
	}
	/**
	 * Check if the certificate is valid for the current time
	 * @return true if is valid
	 */
	private boolean checkValidity() {
		boolean isValid = false;
		Date date = new Date();
		
		try {
			this.cert.checkValidity();
			isValid = true;
			this.addToReport("VALID - Certificate is valid for the current time: "+date);
		} catch (CertificateExpiredException e) {
			this.addToReport("INDETERMINATE/OUT_OF_TIME_BOUNDS - Certificate is expired.");
			isValid = false;
			e.printStackTrace();
		} catch (CertificateNotYetValidException e) {
			this.addToReport("INDETERMINATE/OUT_OF_TIME_BOUNDS - Certificate is not yet valid.");
			e.printStackTrace();
		}
		
		return isValid;
	}
    /**
     * Verification process
     * @param ca root CA's certificate used to validate the end-entity certificate
     * @return true if is valid
     */
	public boolean Validate(X509Certificate ca){
		boolean isValid=false;
		
		
		if(!this.checkSelfSigned()){ 
			if (this.checkKeyUsage()){
				isValid = true;				
			}else isValid = false;
		}
		if (
				this.checkCryptoConstraints() &&
				this.checkValidity() &&
				this.Verify(ca)){
			isValid = true;
		}else isValid = false;
		
		System.out.println("--Certificate constraints validation report-- ");
		for(int i = 0; i<this.report.length;i++){
			if(report[i]!= null)System.out.println(this.report[i]);
		}
		
		return isValid;
	}
	
	/**
	 * Check if the key Usage is set to "nonRepudiantion".
	 * This property is not verified for the root CA's certificate
	 * @return true if is specified
	 */
	private boolean checkKeyUsage(){
		boolean isValid = false;
		boolean usage[] = this.cert.getKeyUsage();
		
		if(usage !=null && usage[1]){
			isValid = true; this.addToReport("VALID - Key usage is set as nonRepudiantion");
			}
		else{
				isValid = false; this.addToReport("INDETERMINATE - Key usage unknown");
			}
		
		return isValid;
	}
	/**
	 * Cryptographic constraints validation
	 * @return
	 */
	private boolean checkCryptoConstraints() {
		boolean isValid = false;
		String oid = this.cert.getSigAlgOID();
		
		if(oid.equals("1.2.840.113549.1.1.13")){
			this.addToReport("VALID - Algorithm SHA512 with RSA");
			isValid = true;}
		else if(oid.equals("1.2.840.113549.1.1.11")){
			this.addToReport("VALID - Algorithm SHA256 with RSA");
			isValid = true;}
		else if(oid.equals("1.2.840.113549.1.1.5")){
			this.addToReport("INVALID/CRYPTO_CONSTRAINTS_FAILURE - Algorithm SHA1 with RSA");
			isValid = false;}
		else if(oid.equals("1.2.840.113549.1.1.4")){
			this.addToReport("INVALID/CRYPTO_CONSTRAINTS_FAILURE - Algorithm MD5 with RSA");
			isValid = false;}
		else{
			this.addToReport("INVALID/CRYPTO_CONSTRAINTS_FAILURE - Unknown");
			isValid = false;
		}
		
		return isValid;
		
	}

	/**
	 * Check if the Certificate is "self-signed"
	 * @return true if the Certificate is self-signed
	 */
	public boolean checkSelfSigned(){
		boolean isValid = false;
		
		if (this.cert.getIssuerDN().equals(this.cert.getSubjectDN())){
			isValid = true; this.addToReport("Certification Authority self-signed certificate");
		}
		
		return isValid;
	}
	/**
	 * Extract the root CA's public key and verify the end-entity certificate
	 * @param ca
	 * @return
	 */
	public boolean Verify(X509Certificate ca){
		PublicKey caPubKey = ca.getPublicKey();
		boolean isValid = false;
		try {
			this.cert.verify(caPubKey);
			isValid = true;
			this.addToReport("VALID - Certificate cryptographic Verification");
			this.addToReport("INFO - Issuer: "+ this.cert.getIssuerDN()+" Subject: "+this.cert.getSubjectDN());
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchProviderException | SignatureException
				| CertificateException e) {
			e.printStackTrace();
			this.addToReport("INVALID/SIG_CRYPTO_FAILURE - Certificate cryptographic Verification");
			isValid = false;
		}
		
		return isValid;
	}
	/**
	* Append a new validation result to a null element of the array.
    * @param s report from a verification method
	*/
	private void addToReport(String s){
		
		int i = this.report.length;
		int j = 0;
		boolean v = false;
		
		while(!v && j<i){
			if(this.report[j] == null){ this.report[j] = s; v= true;}
			
			j++;
		}
		
	}

}

