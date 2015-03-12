package xmlsigmodule;

import xades4j.production.XadesSignatureResult;


public class XAdESSignatureVerifier {
	 XadesSignatureResult result;
	 String report[];
	public XAdESSignatureVerifier(XadesSignatureResult result) {
		
		this.result = result;
		this.report = new String[10];
	}

public boolean SigValidationForm(){
	boolean isValid = false;
	this.checkCanonicalMethod();
	this.checkSignatureMethod();
		
	System.out.println("--Signature Validation Report-- ");
	for(int i = 0; i<this.report.length;i++){
		if(report[i]!= null)System.out.println(this.report[i]);
	}
	return isValid;	
	}

private boolean checkSignatureMethod() {
	// TODO Auto-generated method stub
	boolean isValid = false;
	String cm = this.result.getSignature().getSignedInfo().getCanonicalizationMethodURI();
	if(cm.isEmpty()){isValid = false; this.report[1] = "INVALID/SIG_CONSTRAINTS_FAILURE - Caninicalization Algorithm not specified";}
	else if (cm.equals("http://www.w3.org/2006/12/xml-c14n11")){isValid = true; this.report[1] = "VALID - Caninicalization Algorithm is: http://www.w3.org/2006/12/xml-c14n11";}
	else if (cm.equals("http://www.w3.org/TR/xml-exc-c14n")){isValid = true; this.report[1] = "VALID - Caninicalization Algorithm is: http://www.w3.org/TR/xml-exc-c14n";}
	else if (cm.equals("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")){isValid = true; this.report[1] = "VALID - Caninicalization Algorithm is: http://www.w3.org/TR/2001/REC-xml-c14n-20010315";}
	else {isValid = false; this.report[1] = "INVALID/SIG_CONSTRAINTS_FAILURE - Caninicalization Algorithm not supported";} 
	return isValid;
}

private boolean checkCanonicalMethod() {
	// TODO Auto-generated method stub
	boolean isValid = false;
	String sm = this.result.getSignature().getSignedInfo().getSignatureMethodURI();
	if(sm.equals("")){isValid = false; this.report[2] = "INVALID/SIG_CONSTRAINTS_FAILURE - Signature Algorithm not specified";}
	else if(sm.equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")){isValid = true; this.report[2] = "VALID - Signature Algorithm is http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";}
	else if(sm.equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384")){isValid = true; this.report[2] = "VALID - Signature Algorithm is http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";}
	else if(sm.equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")){isValid = true; this.report[2] = "VALID - Signature Algorithm is http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";}
	else {isValid = false; this.report[2] = "INVALID/CRYPTO_CONSTRAINTS_FAILURE - Signature Algorithm non supported";}
	return isValid;
}
}
