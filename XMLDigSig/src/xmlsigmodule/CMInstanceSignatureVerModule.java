package xmlsigmodule;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

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
import org.xml.sax.SAXException;

public class CMInstanceSignatureVerModule {
	final static String PATH = "file:/C:/Users/axhell/Documents/Github/XMLDigitalSignature/XMLDigSig/";
	
	public static void VerifyCMinsSignature() throws Exception {
		
		BufferedReader br = null;
		InputStream inStream = null;
		String cminstsig = null;
		System.out.println("CM Template Signature file's name: ");
		br = new BufferedReader(new InputStreamReader(System.in));
		try {
			cminstsig = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		Document signature = getDocument(cminstsig);
		
		
		XAdESSignatureValidationModule vv = new XAdESSignatureValidationModule(signature , PATH);
		vv.validate(); 
		
	}
	
	
	/**
     * Load a Document from an XML file
     * @param path The path to the file
     * @return The document extracted from the file
	 * @throws ParserConfigurationException 
	 * @throws IOException 
	 * @throws SAXException 
	 * @throws FileNotFoundException 
     */
    private static Document getDocument(String filename) throws ParserConfigurationException, FileNotFoundException, SAXException, IOException {
       Document signature = null;
    	
    	DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);		
		DocumentBuilder builder = dbf.newDocumentBuilder();
		signature = builder.parse(new FileInputStream(filename));
		
		return signature;
    }
    //BUG
    private static void writeSignedDocumentToFile(Document sigdoc) {
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
