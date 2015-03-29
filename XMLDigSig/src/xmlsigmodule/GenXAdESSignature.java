package xmlsigmodule;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;

import xades4j.XAdES4jException;
import xades4j.algorithms.XPath2FilterTransform.XPath2Filter;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesSignatureResult;
import xades4j.production.XadesSigner;
import xades4j.properties.CommitmentTypeProperty;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.DataObjectFormatProperty;
/**
 * build a XAdES-BES signature 
 */
public class GenXAdESSignature {
    String firstRef;
    String secondRef;
    String baseUri;
	/**
	 * Class constructor
	 * @param cminstfn CM instance relative path
	 * @param cmtfn CM template relative path
	 * @param baseUri URI absolute path 
	 */
    public GenXAdESSignature(String cminstfn, String cmtfn, String baseUri) {
		this.firstRef = cminstfn;
		this.secondRef = cmtfn;
		this.baseUri = baseUri;
	}
    /**
     * Build a XAdES-BES signature for Certification Model 
     * Instance 
     * @param signer
     * @return Document signature
     * @throws Exception
     */
	public Document signCMiXAdESBES(XadesSigner signer) throws Exception {
		/**
		 * Add Certification Model instance as object reference to the signature
		 * Commitment types proof of origin defined in ETSI TS 101 903 V1.4.1 (2009-06)
		 * specify MIME type
		 */
		DataObjectDesc cminst = new DataObjectReference(this.firstRef)
		.withTransform(XPath2Filter.intersect("//*"))
		.withDataObjectFormat(new DataObjectFormatProperty("application/xml"))
		.withCommitmentType(CommitmentTypeProperty.proofOfOrigin())
		;
	
		/** Add Certification Model Template to object reference*/
		DataObjectDesc cmtemp = new DataObjectReference(this.secondRef)
		.withTransform(XPath2Filter.intersect("//*"))
		.withDataObjectFormat(new DataObjectFormatProperty("application/xml"))
		.withCommitmentType(CommitmentTypeProperty.proofOfApproval())
		;
		
		
		/** Create the final signed object with base URI declaration enable relative URI */
		SignedDataObjects alldata = new SignedDataObjects()
				.withSignedDataObject(cminst).withBaseUri(this.baseUri)
				.withSignedDataObject(cmtemp).withBaseUri(this.baseUri)
				;
		
		
		
		/** Create the Document that will hold the resulting XMLSignature */
		DocumentBuilderFactory sigdbf = DocumentBuilderFactory.newInstance();
        sigdbf.setNamespaceAware(true);
        Document sigdoc = sigdbf.newDocumentBuilder().newDocument();
		
        XadesSignatureResult result = null;
        try {
			result = signer.sign(alldata, sigdoc);
		} catch (XAdES4jException e) {
			e.printStackTrace();
		}
        
        XAdESSignatureValidation sv = new XAdESSignatureValidation(result);
        sv.genSigVerifyForm();
        
        /** output the resulting document */
		return sigdoc;
	}
	
	
	
	
/** cancella metodo
	public Document signCMtempXAdESBES(XadesSigner signer) throws Exception {
		
		DataObjectDesc cmtemp = new DataObjectReference(this.firstRef)
		.withTransform(XPath2Filter.union("/*"))
		.withDataObjectFormat(new DataObjectFormatProperty("application/xml"))//MimeTipe qualifying properties
		.withCommitmentType(CommitmentTypeProperty.proofOfOrigin())
		;
		
		SignedDataObjects alldata = new SignedDataObjects()
				.withSignedDataObject(cmtemp)
				.withBaseUri(this.baseUri)
				//.withTransform(new  );
				;
		
		
		
		// Create the Document that will hold the resulting XMLSignature
        DocumentBuilderFactory sigdbf = DocumentBuilderFactory.newInstance();
        sigdbf.setNamespaceAware(true);
        Document sigdoc = sigdbf.newDocumentBuilder().newDocument();
      
		
        XadesSignatureResult result = signer.sign(alldata, sigdoc);
        
        XAdESSignatureValidation sv = new XAdESSignatureValidation(result);
        sv.genSigVerifyForm();
        
        
        //XAdESSignatureValidationModule vv = new XAdESSignatureValidationModule(sigdoc , this.baseUri);
		//vv.validate();
        
        return sigdoc;
        // output the resulting document
        //writeSignedDocumentToFile(sigdoc);
        
     
	}
	*/

}
