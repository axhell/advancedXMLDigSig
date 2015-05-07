package xmlsigmodule;

import java.io.*;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

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

import xades4j.production.*;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.*;
import xades4j.utils.XadesProfileResolutionException;
import xmlsigcore.RSAPrivateKeyReader;


public class CMInstanceSignatureGenModule {
	
	X509CertificateValidation certCA = null;
	X509CertificateValidation certUser = null;
	 
	String cmtempfn; 
	String cminstfn; 
	String cmtsignatureFN;
	String absolutePath; 
	PrivateKey privKuser;
	
	
	
	public CMInstanceSignatureGenModule(String certCAfile, String certUserfile,
			String cmtempfn, String cminstfn, String cmtsignatureFN,
			String absolutePath, String privKuser) {
		
		
		try {
			this.certCA = new X509CertificateValidation(new FileInputStream(certCAfile));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		
		try {
			this.certUser = new X509CertificateValidation(new FileInputStream(certUserfile));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		
		
		
		try {
			this.privKuser = RSAPrivateKeyReader.getPrivKeyFromFile(privKuser);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		this.cmtempfn = cmtempfn;
		this.cminstfn = cminstfn;
		this.cmtsignatureFN = cmtsignatureFN;
		this.absolutePath = absolutePath;
		
		
	}










	/**
	 * Test class to collect input needed to Certification Model Instance signature process
	 * @throws Exception
	 */
	public static void GenCMinstSignature() throws Exception{
		final String PATH = "file:/C:/Users/axhell/Documents/Github/XMLDigitalSignature/XMLDigSig/";
		
		X509CertificateValidation certCA = null;
		X509CertificateValidation certUser = null;
		BufferedReader br = null;
		InputStream inStream = null;
		String certCAfile = null;
		String certUserfile = null;
		String cmtempfn = null;
		String cminstfn = null;
		String cmtsignatureFN = null;

		
		
		//Trust anchor's certificate (root CA)
		System.out.println("Trust Anchor's X509Certificate in DER format: ");
		br = new BufferedReader(new InputStreamReader(System.in));
		try {
			certCAfile = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		inStream = null;
		try {
			inStream = new FileInputStream(certCAfile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		certCA = new X509CertificateValidation(inStream);
				
		
		
		
		//User's certificate.
		System.out.println("User's X509Certificate in DER format: ");
		br = new BufferedReader(new InputStreamReader(System.in));
		try {
			certUserfile = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		inStream = null;
		try {
			inStream = new FileInputStream(certUserfile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		certUser = new X509CertificateValidation(inStream);
		
		PrivateKey privKCA = null;
		try {
			privKCA = RSAPrivateKeyReader.getPrivKeyFromFile("cert/ca_rsa_priveKey.der");
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		PrivateKey privKuser = null;
		try {
			privKuser = RSAPrivateKeyReader.getPrivKeyFromFile("cert/my_rsa_priveKey.der");
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		
		System.out.println("CM Template file's name: ");
		br = new BufferedReader(new InputStreamReader(System.in));
		try {
			cmtempfn = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		
		
		
		System.out.println("CM Template Signature file's name: ");
		br = new BufferedReader(new InputStreamReader(System.in));
		try {
			cmtsignatureFN = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		Document cmtsignature = getDocument(cmtsignatureFN);
		
		
		
		System.out.println("CM Instance file's name: ");
		br = new BufferedReader(new InputStreamReader(System.in));
		try {
			cminstfn = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		
	
		
		inStream.close();
		
		System.out.println("Trust Anchor certificate validation:");
		boolean tacert = certCA.Validate(certCA.cert);
		System.out.println();
		System.out.println("User certificate validation:");
		boolean ucert = certUser.Validate(certCA.cert);
		
		/**
		System.out.println();
		System.out.println("Certification Model Template signature validation: ");
		//create CM template signature for test only
		XadesSigner signerCMT = getSigner(certCA.cert, privKCA);
		//genara firma
		GenXAdESSignature newSig = new GenXAdESSignature(cmtempfn , null, PATH);
		//Sign
		Document sigCMT = newSig.signCMtempXAdESBES(signerCMT);
		writeSignedDocumentToFile(sigCMT);
		*/
		XAdESSignatureValidationModule vv = new XAdESSignatureValidationModule(cmtsignature , certCA.cert, PATH);
		boolean cmt = vv.validate();  
		
		System.out.println();		
		
		
		
		/**
		 * CM instance signature process only if 
		 * trust anchor's certificate AND user's certificate AND CM template's signature
		 * are valid.
		 */
		if(tacert && ucert && cmt){
			
			/** Create a signer for the Certification Model Instance */
			XadesSigner signerCMI = getSigner(certUser.cert, privKuser);
			/** Generate the signature content */
			GenXAdESSignature newSigI = new GenXAdESSignature(cminstfn, cmtempfn, PATH);
			/** Sign */
			Document sigCMI = newSigI.signCMiXAdESBES(signerCMI);
			System.out.println();
			System.out.println("Certification Model Instance signature validation: ");
			XAdESSignatureValidationModule vi = new XAdESSignatureValidationModule(sigCMI , certCA.cert, PATH);
				if(vi.validate()){
					writeSignedDocumentToFile(sigCMI);
					System.out.println();
					System.out.println("Certification Model Instance signed correctly");
				}	
		}else{
			System.out.println();
			System.out.println("Error, Certification Model Instance not signed");
		}
		
	}

	
	       
	
	
	/**
	 * Create XadesSigner object representing user for CM instance signature process.
	 * @param cert User's X509Certificate
	 * @param privK User's RSA private key
	 * @return XadesSigner object
	 */
	private static XadesSigner getSigner(X509Certificate cert, PrivateKey privK) {
		try {
			KeyingDataProvider kp = new DirectKeyingDataProvider(cert, privK);
			XadesSigningProfile p = new XadesBesSigningProfile(kp);
			return p.newSigner();
			} catch (XadesProfileResolutionException e) {
				e.printStackTrace();
			}
		return null;
		
		
	}
	
	/**
     * Load a Document from an XML file
     * @param filename Relative path to the file
     * @return The document parsed from the file
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





	public Document sign() throws Exception {
		
		System.out.println("Trust Anchor certificate validation:");
		boolean tacert = this.certCA.Validate(this.certCA.cert);
		System.out.println();
		System.out.println("User certificate validation:");
		boolean ucert = this.certUser.Validate(this.certCA.cert);
		
		System.out.println();
		System.out.println("Certification Model Template signature validation: ");
		//create CM template signature for test only
		//Get CA's private key
		PrivateKey privKCA = null;
		try {
			privKCA = RSAPrivateKeyReader.getPrivKeyFromFile("cert/ca_rsa_priveKey.der");
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		XadesSigner signerCMT = getSigner(this.certCA.cert, privKCA);
		//genara firma
		GenXAdESSignature newSig = new GenXAdESSignature(this.cmtempfn , null, this.absolutePath);
		//Sign
		Document sigCMT = newSig.signCMtempXAdESBES(signerCMT);
		//writeSignedDocumentToFile(sigCMT);
		
		XAdESSignatureValidationModule vv = new XAdESSignatureValidationModule(sigCMT , this.certCA.cert, this.absolutePath);
		boolean cmt = vv.validate();  
		
		System.out.println();
		
		
		
		/**
		 * CM instance signature process only if 
		 * trust anchor's certificate AND user's certificate AND CM template's signature
		 * are valid.
		 */
		Document sigCMI = null;
		if(tacert && ucert && cmt){
			
			/** Create a signer for the Certification Model Instance */
			XadesSigner signerCMI = getSigner(this.certUser.cert, this.privKuser);
			/** Generate the signature content */
			GenXAdESSignature newSigI = new GenXAdESSignature(this.cminstfn, this.cmtempfn, this.absolutePath);
			/** Sign */
			sigCMI = newSigI.signCMiXAdESBES(signerCMI);
			System.out.println();
			System.out.println("Certification Model Instance signature validation: ");
			XAdESSignatureValidationModule vi = new XAdESSignatureValidationModule(sigCMI , this.certCA.cert, this.absolutePath);
				if(vi.validate()){
					//writeSignedDocumentToFile(sigCMI);
					System.out.println();
					System.out.println("Certification Model Instance signed correctly");
					
				}	
		}else{
			System.out.println();
			System.out.println("Error, Certification Model Instance not signed");
		}
		
		return sigCMI;
	}
}
