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
	this.checkSignatureForm(this.verResult.getSignatureForm());
	this.checkSignatureMethod(this.verResult.getCanonicalizationAlgorithmUri());
	this.checkCanonicalMethod(this.verResult.getSignatureAlgorithmUri());
	this.addToReport("VALID - Signature cryptographic verification");
	System.out.println("--Signature constraints validation report-- ");
	for(int i = 0; i<this.report.length;i++){
		if(report[i]!= null)System.out.println(this.report[i]);
		}
	
	return isValid;
}


private boolean checkSignatureForm(XAdESForm sf) {
	boolean isValid = false;
	
	if(sf==null){this.addToReport("INVALID/SIG_CONSTRAINTS_FAILURE - Signature form not supported") ;}
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
	// TODO Auto-generated method stub
	boolean isValid = false;
	if(cm.isEmpty()){isValid = false; this.addToReport("INVALID/SIG_CONSTRAINTS_FAILURE - Caninicalization Algorithm not specified");}
	else if (cm.equals("http://www.w3.org/2006/12/xml-c14n11")){isValid = true; this.addToReport("VALID - Caninicalization Algorithm is: http://www.w3.org/2006/12/xml-c14n11");}
	else if (cm.equals("http://www.w3.org/TR/xml-exc-c14n")){isValid = true; this.addToReport("VALID - Caninicalization Algorithm is: http://www.w3.org/TR/xml-exc-c14n");}
	else if (cm.equals("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")){isValid = true; this.addToReport("VALID - Caninicalization Algorithm is: http://www.w3.org/TR/2001/REC-xml-c14n-20010315");}
	else {isValid = false; this.addToReport("INVALID/SIG_CONSTRAINTS_FAILURE - Caninicalization Algorithm not supported");} 
	return isValid;
}

private boolean checkCanonicalMethod(String sm) {
	// TODO Auto-generated method stub
	boolean isValid = false;
	if(sm.equals("")){isValid = false; this.addToReport("INVALID/SIG_CONSTRAINTS_FAILURE - Signature Algorithm not specified");}
	else if(sm.equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")){isValid = true; this.addToReport("VALID - Signature Algorithm is http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");}
	else if(sm.equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384")){isValid = true; this.addToReport("VALID - Signature Algorithm is http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");}
	else if(sm.equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")){isValid = true; this.addToReport("VALID - Signature Algorithm is http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");}
	else {isValid = false; this.addToReport("INVALID/CRYPTO_CONSTRAINTS_FAILURE - Signature Algorithm non supported");}
	return isValid;
}

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
