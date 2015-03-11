package xmlsigmodule;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Date;

import javax.security.cert.CertificateEncodingException;
import javax.security.cert.CertificateException;
import javax.security.cert.CertificateExpiredException;
import javax.security.cert.CertificateNotYetValidException;
import javax.security.cert.X509Certificate;

public class X509CertificateValidation {
	X509Certificate cert;
	//The report include results for cryptographic constraints, 
	//chain of certificate, trust anchors constraints
	private String[] report;
	
	X509CertificateValidation(InputStream inStream){
		try {
			this.cert = X509Certificate.getInstance(inStream);
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		};
		
		this.report = new String[10];
	}
	
	public void ValidateRootCA(X509Certificate ca){
		this.Verify(ca);
		this.ValidateCryptoConstraints();
		this.checkValidity();
		System.out.println("validate report: ");
		for(int i = 0; i<this.report.length;i++){
			if(report[i]!= null)System.out.println(this.report[i]);
		}
	}
	
	private boolean checkValidity() {
		// TODO Auto-generated method stub
		boolean isValid = false;
		Date date = new Date();
		
		try {
			this.cert.checkValidity();
			isValid = true;
			this.report[2]= "VALID - Certificate is valid for the current time: "+date;
		} catch (CertificateExpiredException e) {
			this.report[2]= "INDETERMINATE/OUT_OF_TIME_BOUNDS - Certificate is expired.";
			isValid = false;
			e.printStackTrace();
		} catch (CertificateNotYetValidException e) {
			this.report[2]= "INDETERMINATE/OUT_OF_TIME_BOUNDS - Certificate is not yet valid.";
			e.printStackTrace();
		}
		
		return isValid;
	}

	public void Validate(X509Certificate ca){
		this.Verify(ca);
		this.ValidateCryptoConstraints();
		this.checkValidity();
		System.out.println("Validation Report: ");
		for(int i = 0; i<this.report.length;i++){
			if(report[i]!= null)System.out.println(this.report[i]);
		}
	}
	
	
	private boolean ValidateCryptoConstraints() {
		boolean isValid = false;
		String oid = this.cert.getSigAlgOID();
		
		if(oid.equals("1.2.840.113549.1.1.13")){this.report[1] = "VALID - Algorithm SHA512 with RSA";   isValid = true;}
		else if(oid.equals("1.2.840.113549.1.1.11")){this.report[1] = "VALID - Algorithm SHA256 with RSA";   isValid = true;}
		else if(oid.equals("1.2.840.113549.1.1.5")){this.report[1] = "INVALID/CRYPTO_CONSTRAINTS_FAILURE - Algorithm SHA1 with RSA";   isValid = false;}
		else if(oid.equals("1.2.840.113549.1.1.4")){this.report[1] = "INVALID/CRYPTO_CONSTRAINTS_FAILURE - Algorithm MD5 with RSA";   isValid = false;}
		else{
			this.report[1] = "INVALID/CRYPTO_CONSTRAINTS_FAILURE - Unknown";   isValid = false;
		}
		
		return isValid;
		
	}


	public boolean Verify(X509Certificate ca){
		PublicKey caPubKey = ca.getPublicKey();
		boolean isValid = false;
		try {
			this.cert.verify(caPubKey);
			isValid = true;
			this.report[0] = "VALID - Cryptographic Verification";
			this.report[9] = "INFO - Issuer: "+ this.cert.getIssuerDN()+" Subject: "+this.cert.getSubjectDN();
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchProviderException | SignatureException
				| CertificateException e) {
			e.printStackTrace();
			this.report[0] = "INVALID/SIG_CRYPTO_FAILURE - Cryptographic Verification";
			isValid = false;
		}
		
		return isValid;
	}
	
	public void showAlgo(){
		System.out.println("Algorithm OID: "+this.cert.getSigAlgOID());
	}



	public void show() {
		System.out.println(this.cert.toString());
		
	}

}
