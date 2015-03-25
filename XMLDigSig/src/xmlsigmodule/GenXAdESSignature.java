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

public class GenXAdESSignature {
    String firstRef;
    String secondRef;
    String baseUri;
	
    public GenXAdESSignature(String cminstfn, String cmtfn, String baseUri) {
		this.firstRef = cminstfn;
		this.secondRef = cmtfn;
		this.baseUri = baseUri;
	}

	public Document signCMiXAdESBES(XadesSigner signer) throws Exception {
		/**
		 * Add Certification Model instance to reference
		 * Commitment types proof of origin defined in ETSI TS 101 903 V1.4.1 (2009-06)
		 */
		DataObjectDesc cminst = new DataObjectReference(this.firstRef)
		.withTransform(XPath2Filter.intersect("/"))
		.withDataObjectFormat(new DataObjectFormatProperty("application/xml"))//MimeType
		.withCommitmentType(CommitmentTypeProperty.proofOfOrigin())//Signer is creator of the reference
		;
	
		/**
		 * Add Certification Model Template to reference
		 * Commitment types proof of origin defined in ETSI TS 101 903 V1.4.1 (2009-06)
		 */
		DataObjectDesc cmtemp = new DataObjectReference(this.secondRef)
		.withTransform(XPath2Filter.intersect("/"))
		.withDataObjectFormat(new DataObjectFormatProperty("application/xml"))//MimeTipe qualify
		.withCommitmentType(CommitmentTypeProperty.proofOfApproval())//Signer approved only the reference
		;
		
		
		/**
		 * Create the final signed object with base uri declaration enable relative uri
		 */
		SignedDataObjects alldata = new SignedDataObjects()
				.withSignedDataObject(cminst).withBaseUri(this.baseUri)
				.withSignedDataObject(cmtemp).withBaseUri(this.baseUri)
				;
		
		
		
		// Create the Document that will hold the resulting XMLSignature
		DocumentBuilderFactory sigdbf = DocumentBuilderFactory.newInstance();
        sigdbf.setNamespaceAware(true);
        Document sigdoc = sigdbf.newDocumentBuilder().newDocument();
		
        XadesSignatureResult result = null;
        try {
			result = signer.sign(alldata, sigdoc);
		} catch (XAdES4jException e) {
			e.printStackTrace();
		}
        
        XAdESSignatureVerifier sv = new XAdESSignatureVerifier(result);
        sv.genSigVerifyForm();
        
        //output the resulting document
		return sigdoc;
	}
	
	
	
	
//cancella metodo
	public Document signCMtempXAdESBES(XadesSigner signer) throws Exception {
		/**
		 * Add the object reference to the signature
		 */
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
		/**
		* Commitment types defined in ETSI TS 101 903 V1.4.1 (2009-06).
		* section 7.2.6.
		*/
		
		
		// Create the Document that will hold the resulting XMLSignature
        DocumentBuilderFactory sigdbf = DocumentBuilderFactory.newInstance();
        sigdbf.setNamespaceAware(true);
        Document sigdoc = sigdbf.newDocumentBuilder().newDocument();
      
		
        XadesSignatureResult result = signer.sign(alldata, sigdoc);
        
        XAdESSignatureVerifier sv = new XAdESSignatureVerifier(result);
        sv.genSigVerifyForm();
        
        
        //XAdESSignatureValidationModule vv = new XAdESSignatureValidationModule(sigdoc , this.baseUri);
		//vv.validate();
        
        return sigdoc;
        // output the resulting document
        //writeSignedDocumentToFile(sigdoc);
        
     
	}
	

}
