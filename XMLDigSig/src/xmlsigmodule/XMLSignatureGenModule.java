package xmlsigmodule;

import java.io.*;
import java.security.PrivateKey;

import javax.security.cert.CertificateEncodingException;

import xades4j.algorithms.XPath2FilterTransform.XPath2Filter;
import xades4j.production.*;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.DataObjectFormatProperty;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.*;
import xades4j.utils.XadesProfileResolutionException;
import xmlsigcore.RSAPrivateKeyReader;


public class XMLSignatureGenModule {
	public static void GenCMinstSignature() throws IOException, CertificateEncodingException{
		
		X509CertificateValidation certCA = null;
		X509CertificateValidation certUser = null;
		BufferedReader br = null;
		InputStream inStream = null;
		String certCAfile = null;
		String certUserfile = null;
		
		
		//Definition of the Trust anchors, root CA certificate with pub key.
		System.out.println("Root CA's certificate in DER format: ");
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
				
		
		
		
		//User certificate with pub key.
		System.out.println("User's certificate in DER format: ");
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
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		certUser = new X509CertificateValidation(inStream);
		
		PrivateKey privKCA = null;
		try {
			privKCA = RSAPrivateKeyReader.getPrivKeyFromFile("cert/rooCA.der");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		KeyingDataProvider kp = new DirectKeyingDataProvider(certCA.cert, privKCA);
		XadesSigningProfile p = new XadesBesSigningProfile(kp);
		try {
			XadesSigner signer = p.newSigner();
		} catch (XadesProfileResolutionException e) {
			e.printStackTrace();
		}
		
		DataObjectDesc cmtemp = new DataObjectReference("CMtemp.xml")
				.withTransform(XPath2Filter.intersect("/"))
				.withDataObjectFormat(new DataObjectFormatProperty("application/xml"))//MimeTipe qualify
				.withDataObjectTimeStamp();//timestamp qualify
		SignedDataObjects objs = new SignedDataObjects(cmtemp);
		//CM template verifica
		//System.out.println("Certification Model Template (URI): ");
		//Altri input?
		//System.out.println("Optional input(blank to skip): ");
		
		
		
		inStream.close();
		
		//output risultati
		//certCA.show();
		certCA.ValidateRootCA(certCA.cert);
		//certUser.show();
		certUser.Validate(certCA.cert);
		
		
		//genara firma
		//Reference //CM insta, CM template, optional
		//Canonicali
		
		//Firma
		
	}
}
