package xmlsigmodule;

import xades4j.production.XadesSignatureResult;
import xades4j.verification.XAdESForm;
import xades4j.verification.XAdESVerificationResult;


public class XAdESSignatureVerifier {
	 XadesSignatureResult genResult;
	 XAdESVerificationResult verResult;
	 String report[];
	public XAdESSignatureVerifier(XadesSignatureResult result) {
		
		this.genResult = result;
		this.report = new String[10];
	}


public XAdESSignatureVerifier(XAdESVerificationResult result) {
	this.verResult = result;
	this.report = new String[10];
	}


public boolean genSigVerifyForm(){
	boolean isValid = false;
	this.checkCanonicalMethod(this.genResult.getSignature().getSignedInfo().getSignatureMethodURI());
	this.checkSignatureMethod(this.genResult.getSignature().getSignedInfo().getCanonicalizationMethodURI());
	System.out.println("--Signature constraints validation report-- ");
	for(int i = 0; i<this.report.length;i++){
		if(report[i]!= null)System.out.println(this.report[i]);
		}
	return isValid;	
	}

public boolean ValSigVerifyForm() {
	boolean isValid = false;
	
	this.checkCanonicalMethod(this.verResult.getSignatureAlgorithmUri());
	this.checkSignatureMethod(this.verResult.getCanonicalizationAlgorithmUri());
	this.checkSignatureForm(this.verResult.getSignatureForm());
	System.out.println("--Signature constraints validation report-- ");
	for(int i = 0; i<this.report.length;i++){
		if(report[i]!= null)System.out.println(this.report[i]);
		}
	
	return isValid;
}


private boolean checkSignatureForm(XAdESForm sf) {
	boolean isValid = false;
	
	if(sf==null){this.report[3] = "INVALID/SIG_CONSTRAINTS_FAILURE - Signature form not supported" ;}
	else if(sf == XAdESForm.BES){isValid = true; this.report[3] = "VALID - Signature form is XAdES-BES" ;}
	else if(sf == XAdESForm.T){isValid = true; this.report[3] = "VALID - Signature form is XAdES-T" ;}
	
	return isValid;
	
}


private boolean checkSignatureMethod(String cm) {
	// TODO Auto-generated method stub
	boolean isValid = false;
	if(cm.isEmpty()){isValid = false; this.report[1] = "INVALID/SIG_CONSTRAINTS_FAILURE - Caninicalization Algorithm not specified";}
	else if (cm.equals("http://www.w3.org/2006/12/xml-c14n11")){isValid = true; this.report[1] = "VALID - Caninicalization Algorithm is: http://www.w3.org/2006/12/xml-c14n11";}
	else if (cm.equals("http://www.w3.org/TR/xml-exc-c14n")){isValid = true; this.report[1] = "VALID - Caninicalization Algorithm is: http://www.w3.org/TR/xml-exc-c14n";}
	else if (cm.equals("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")){isValid = true; this.report[1] = "VALID - Caninicalization Algorithm is: http://www.w3.org/TR/2001/REC-xml-c14n-20010315";}
	else {isValid = false; this.report[1] = "INVALID/SIG_CONSTRAINTS_FAILURE - Caninicalization Algorithm not supported";} 
	return isValid;
}

private boolean checkCanonicalMethod(String sm) {
	// TODO Auto-generated method stub
	boolean isValid = false;
	if(sm.equals("")){isValid = false; this.report[2] = "INVALID/SIG_CONSTRAINTS_FAILURE - Signature Algorithm not specified";}
	else if(sm.equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")){isValid = true; this.report[2] = "VALID - Signature Algorithm is http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";}
	else if(sm.equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384")){isValid = true; this.report[2] = "VALID - Signature Algorithm is http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";}
	else if(sm.equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")){isValid = true; this.report[2] = "VALID - Signature Algorithm is http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";}
	else {isValid = false; this.report[2] = "INVALID/CRYPTO_CONSTRAINTS_FAILURE - Signature Algorithm non supported";}
	return isValid;
}



}
