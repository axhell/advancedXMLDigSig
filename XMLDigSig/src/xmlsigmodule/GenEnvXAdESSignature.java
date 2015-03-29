package xmlsigmodule;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.xml.crypto.dsig.Transform;
import javax.xml.parsers.DocumentBuilder;
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
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import xades4j.XAdES4jException;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.algorithms.XPath2FilterTransform.XPath2Filter;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSignatureResult;
import xades4j.production.XadesSigner;
import xades4j.production.XadesSigningProfile;
import xades4j.properties.AllDataObjsCommitmentTypeProperty;
import xades4j.properties.CommitmentTypeProperty;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.DataObjectTransform;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.DirectKeyingDataProvider;
import xades4j.utils.XadesProfileResolutionException;

public class GenEnvXAdESSignature {
	
	String objectDoc;

	

	public GenEnvXAdESSignature(String objectDoc){
		
		
		this.objectDoc = objectDoc;     
        
	}
	
	
	public void signCMtempXAdESBES(XadesSigner signer) throws XAdES4jException {

		Document source = getDocument(objectDoc);
		Element sigParent = (Element) source.getDocumentElement();
		Element elemToSign = source.getDocumentElement();
		String refUri;
        if (elemToSign.hasAttribute("Id")) {
            refUri = '#' + elemToSign.getAttribute("Id");
        } else {
            if (elemToSign.getParentNode().getNodeType() != Node.DOCUMENT_NODE) {
                throw new IllegalArgumentException("Element without Id must be the document root");
            }
            refUri = "";
        }
        
        DataObjectDesc objectRef = new DataObjectReference(refUri)
        							.withTransform(new EnvelopedSignatureTransform())
        							.withCommitmentType(CommitmentTypeProperty.proofOfOrigin())
        							;
        
        SignedDataObjects alldata = new SignedDataObjects()
									.withSignedDataObject(objectRef)
									;
        //Sign
        XadesSignatureResult result = signer.sign(alldata, sigParent);
        
         //Output Report
        XAdESSignatureValidation sv = new XAdESSignatureValidation(result);
        sv.genSigVerifyForm();
        
        writeSignedDocumentToFile(source);
		
	}
	
	
	private void writeSignedDocumentToFile(Document source) {
		OutputStream os2 = null;
        try {
			os2 = new FileOutputStream("CMTSignature.xml");
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
			trans.transform(new DOMSource(source), new StreamResult(os2));
		} catch (TransformerException e) {
			e.printStackTrace();
		}
		
	}

	
	/**
     * Load a Document from an XML file
     * @param path The path to the file
     * @return The document extracted from the file
     */
    private static Document getDocument(String filename) {
       
    	DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);		
		DocumentBuilder builder = null;
		try {
			builder = dbf.newDocumentBuilder();
		} catch (ParserConfigurationException e2) {
			e2.printStackTrace();
		}
		Document signature = null;
		try {
			signature = builder.parse(new FileInputStream(filename));
		} catch (SAXException e1) {
			e1.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
    
		return signature;
    }

	

}
