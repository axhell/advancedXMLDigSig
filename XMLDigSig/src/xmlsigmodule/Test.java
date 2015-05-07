package xmlsigmodule;

import org.w3c.dom.Document;



public class Test {

	/**
	 * 
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		
		
		String certCAfile = null; //CA's certificate file relative path.
		String certUserfile = null; //User's certificate file relative path.
		String cmtempfn = null; //CM template file relative path.
		String cminstfn = null; //CM instance file relative path.
		String cmtsignatureFN = null; //CM template signature file relative path.
		String absolutePath = null; //URI for both CM Template and Instance.
		String privKuser = null; //User private key file relative path.
		
		
		CMInstanceSignatureGenModule cmiSignature = new CMInstanceSignatureGenModule(certCAfile, certUserfile, cmtempfn, cminstfn, cmtsignatureFN, absolutePath, privKuser);
		
		
		
		Document signature = cmiSignature.sign();
		
	}
}