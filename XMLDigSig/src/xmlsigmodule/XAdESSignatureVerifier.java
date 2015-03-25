package xmlsigmodule;

import xades4j.production.XadesSignatureResult;
import xades4j.verification.XAdESForm;
import xades4j.verification.XAdESVerificationResult;

/**
 * Sets of method used to collect report with details of constraints verification process.
 */
public class XAdESSignatureVerifier {
	 XadesSignatureResult genResult;
	 XAdESVerificationResult verResult;
	 String report[];
/**
 * Class constructor. Create an object including XadesSignatureResult object 
 * and a report used to validate signature after generation process 	 
 * @param result XadesSignatureResult object containing 
 * 				all information about signature validation
 */
public XAdESSignatureVerifier(XadesSignatureResult result) {
	this.genResult = result;
	this.report = new String[10];
	}

/**
 * 
 * @param result
 */
public XAdESSignatureVerifier(XAdESVerificationResult result) {
	this.verResult = result;
	this.report = new String[10];
	}

/**
 * Return the report of all verification method for the XadesSignatureResult object.
 * @return true if all method return true, otherwise return false.
 */
public boolean genSigVerifyForm(){
	boolean isValid = false;
	if (
			this.checkCanonicalMethod(this.genResult.getSignature().getSignedInfo().getSignatureMethodURI()) &&
			this.checkSignatureMethod(this.genResult.getSignature().getSignedInfo().getCanonicalizationMethodURI())){
		isValid = true;
	}
	System.out.println("--Signature constraints validation report-- ");
	for(int i = 0; i<this.report.length;i++){
		if(report[i]!= null)System.out.println(this.report[i]);
		}
	return isValid;	
	}
/**
 * Return the report of all verification method for the XAdESVerificationResult object.
 * @return true if all method return true, otherwise return false.
 */
public boolean ValSigVerifyForm() {
	boolean isValid = false;
	if ( 
			this.checkSignatureForm(this.verResult.getSignatureForm()) &&
			this.checkSignatureMethod(this.verResult.getCanonicalizationAlgorithmUri()) &&
			this.checkCanonicalMethod(this.verResult.getSignatureAlgorithmUri())){
		isValid = true;
	}
		
	this.addToReport("VALID - Signature cryptographic verification");
	System.out.println("--Signature constraints validation report-- ");
	for(int i = 0; i<this.report.length;i++){
		if(report[i]!= null)System.out.println(this.report[i]);
		}
	
	return isValid;
}

/**
 * This method check if the form of the signature is accepted
 * @param sf XAdESForm object
 * @return true if the 
 */
private boolean checkSignatureForm(XAdESForm sf) {
	boolean isValid = false;
	
	if(sf==null) {isValid = false; this.addToReport("INVALID/SIG_CONSTRAINTS_FAILURE - Signature form not supported") ;}
	else if(sf == XAdESForm.BES){isValid = true; this.addToReport("VALID - Signature form is XAdES-BES") ;}
	else if(sf == XAdESForm.T){isValid = true; this.addToReport("VALID - Signature form is XAdES-T");}
	else if(sf == XAdESForm.EPES){isValid = true; this.addToReport("VALID - Signature form is XAdES-EPES");}
	else if(sf == XAdESForm.C){isValid = true; this.addToReport("VALID - Signature form is XAdES-C");}
	else if(sf == XAdESForm.X){isValid = true; this.addToReport("VALID - Signature form is XAdES-X");}
	else if(sf == XAdESForm.X_L){isValid = true; this.addToReport("VALID - Signature form is XAdES-X_L");}
	else if(sf == XAdESForm.A){isValid = true; this.addToReport("VALID - Signature form is XAdES-A");}
	
	return isValid;
	
}


private boolean checkSignatureMethod(String cm) {
	boolean isValid = false;
	if(cm.isEmpty()){isValid = false; this.addToReport("INVALID/SIG_CONSTRAINTS_FAILURE - Caninicalization Algorithm not specified");}
	else if (cm.equals("http://www.w3.org/2006/12/xml-c14n11")){isValid = true; this.addToReport("VALID - Caninicalization Algorithm is: http://www.w3.org/2006/12/xml-c14n11");}
	else if (cm.equals("http://www.w3.org/TR/xml-exc-c14n")){isValid = true; this.addToReport("VALID - Caninicalization Algorithm is: http://www.w3.org/TR/xml-exc-c14n");}
	else if (cm.equals("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")){isValid = true; this.addToReport("VALID - Caninicalization Algorithm is: http://www.w3.org/TR/2001/REC-xml-c14n-20010315");}
	else {isValid = false; this.addToReport("INVALID/SIG_CONSTRAINTS_FAILURE - Caninicalization Algorithm not supported");} 
	return isValid;
}

private boolean checkCanonicalMethod(String sm) {
	boolean isValid = false;
	if(sm.equals("")){isValid = false; this.addToReport("INVALID/SIG_CONSTRAINTS_FAILURE - Signature Algorithm not specified");}
	else if(sm.equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")){isValid = true; this.addToReport("VALID - Signature Algorithm is http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");}
	else if(sm.equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384")){isValid = true; this.addToReport("VALID - Signature Algorithm is http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");}
	else if(sm.equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")){isValid = true; this.addToReport("VALID - Signature Algorithm is http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");}
	else {isValid = false; this.addToReport("INVALID/CRYPTO_CONSTRAINTS_FAILURE - Signature Algorithm non supported");}
	return isValid;
}
/**
 * Append a new String object to a null element of the report array
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
