package xmlsigmodule;

import java.io.*;

import javax.security.cert.CertificateEncodingException;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

public class XMLSignatureGenModule {
	public static void GenCMinstSignature() throws IOException, CertificateEncodingException{
		
		X509CertificateValidation certCA = null;
		X509CertificateValidation certUser = null;
		BufferedReader br = null;
		InputStream inStream = null;
		String certCAfile = null;
		String certUserfile = null;
		
		
		//Trust anchors root CA
		System.out.println("Root CA's certificate in DER format: ");
		br = new BufferedReader(new InputStreamReader(System.in));
		try {
			certCAfile = br.readLine();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		inStream = null;
		try {
			inStream = new FileInputStream(certCAfile);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		certCA = new X509CertificateValidation(inStream);
		
		
		
		
		
		
		//Certificato utente + private
		System.out.println("User's certificate in DER format: ");
		br = new BufferedReader(new InputStreamReader(System.in));
		try {
			certUserfile = br.readLine();
		} catch (IOException e) {
			// TODO Auto-generated catch block
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
		
		//CM template verifica
		System.out.println("Certification Model Template (URI): ");
		//Altri input?
		System.out.println("Optional input(blank to skip): ");
		
		
		
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
