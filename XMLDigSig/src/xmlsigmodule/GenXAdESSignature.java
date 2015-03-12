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

import xades4j.XAdES4jException;
import xades4j.algorithms.XPath2FilterTransform.XPath2Filter;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesSignatureResult;
import xades4j.production.XadesSigner;
import xades4j.properties.AllDataObjsCommitmentTypeProperty;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.DataObjectFormatProperty;

public class GenXAdESSignature {
    String cminstance;
    String cmtemplate;
	public GenXAdESSignature(String cminstancepath, String cmtpath) {
		this.cminstance = cminstancepath;
		this.cmtemplate = cmtpath;
	}

	public void signCMiXAdESBES(XadesSigner signer) {
		/**
		 * Add the object reference to the signature
		 */
		DataObjectDesc cminst = new DataObjectReference(this.cminstance)
		.withTransform(XPath2Filter.intersect("/"))
		.withDataObjectFormat(new DataObjectFormatProperty("application/xml"))//MimeTipe qualify
		;
	
		DataObjectDesc cmtemp = new DataObjectReference(this.cmtemplate)
		.withTransform(XPath2Filter.intersect("/"))
		.withDataObjectFormat(new DataObjectFormatProperty("application/xml"))//MimeTipe qualify
		;
		
		
		
		
		SignedDataObjects alldata = new SignedDataObjects()
				.withSignedDataObject(cminst).withBaseUri(this.cminstance)
				.withSignedDataObject(cmtemp).withBaseUri(this.cmtemplate)
				;
		/**
		* Commitment types defined in ETSI TS 101 903 V1.4.1 (2009-06).
		* section 7.2.6.
		*/
		alldata.withCommitmentType(AllDataObjsCommitmentTypeProperty.proofOfApproval());
		alldata.withCommitmentType(AllDataObjsCommitmentTypeProperty.proofOfCreation());
		alldata.withCommitmentType(AllDataObjsCommitmentTypeProperty.proofOfDelivery());
		alldata.withCommitmentType(AllDataObjsCommitmentTypeProperty.proofOfOrigin());
		alldata.withCommitmentType(AllDataObjsCommitmentTypeProperty.proofOfReceipt());
		alldata.withCommitmentType(AllDataObjsCommitmentTypeProperty.proofOfSender());
		
		
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
        sv.SigValidationForm();
        
        // output the resulting document
        OutputStream os2 = null;
        try {
			os2 = new FileOutputStream("CMInstance.xml");
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
        //os2 = System.out;

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
