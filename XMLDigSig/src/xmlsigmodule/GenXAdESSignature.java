package xmlsigmodule;


import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStream;





import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

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
	
    public GenXAdESSignature(String cminstancepath, String cmtpath, String baseUri) {
		this.firstRef = cminstancepath;
		this.secondRef = cmtpath;
		this.baseUri = baseUri;
	}

	public void signCMiXAdESBES(XadesSigner signer) {
		/**
		 * Add the object reference to the signature
		 */
		DataObjectDesc cminst = new DataObjectReference(this.firstRef)
		.withTransform(XPath2Filter.intersect("/"))
		.withDataObjectFormat(new DataObjectFormatProperty("application/xml"))//MimeTipe qualify
		;
	
		DataObjectDesc cmtemp = new DataObjectReference(this.secondRef)
		.withTransform(XPath2Filter.intersect("/"))
		.withDataObjectFormat(new DataObjectFormatProperty("application/xml"))//MimeTipe qualify
		;
		
		
		
		
		SignedDataObjects alldata = new SignedDataObjects()
				.withSignedDataObject(cminst).withBaseUri(this.baseUri)
				.withSignedDataObject(cmtemp).withBaseUri(this.baseUri)
				;
		/**
		* Commitment types defined in ETSI TS 101 903 V1.4.1 (2009-06).
		* section 7.2.6.
		*/
		
		
		// Create the Document that will hold the resulting XMLSignature
        DocumentBuilderFactory sigdbf = DocumentBuilderFactory.newInstance();
        sigdbf.setNamespaceAware(true);
        Document sigdoc = null;
        try {
			sigdoc = sigdbf.newDocumentBuilder().newDocument();
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		}
		
        XadesSignatureResult result = null;
        try {
			result = signer.sign(alldata, sigdoc);
		} catch (XAdES4jException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        XAdESSignatureVerifier sv = new XAdESSignatureVerifier(result);
        sv.genSigVerifyForm();
        
        // output the resulting document
       writeSignedDocumentToFile(sigdoc);
        
              
		
	}
	
	
	
	

	public void signCMtempXAdESBES(XadesSigner signer) throws Exception {
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
        
        
        XAdESSignatureValidationModule vv = new XAdESSignatureValidationModule(sigdoc , "file:/C:/Users/axhell/Documents/Github/XMLDigitalSignature/XMLDigSig/");
		vv.validate();
        
        
        // output the resulting document
        writeSignedDocumentToFile(sigdoc);
        
     
	}
	
	private void writeSignedDocumentToFile(Document sigdoc) {
		OutputStream os2 = null;
        try {
			os2 = new FileOutputStream("CMISignature.xml");
		} catch (FileNotFoundException e1) {
		
			e1.printStackTrace();
		}

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = null;
		try {
			trans = tf.newTransformer();
		} catch (TransformerConfigurationException e) {
			e.printStackTrace();
		}
        trans.setOutputProperty(OutputKeys.INDENT, "yes");
        try {
			trans.transform(new DOMSource(sigdoc), new StreamResult(os2));
		} catch (TransformerException e) {
			e.printStackTrace();
		}
		
        
   
	}
	
}
