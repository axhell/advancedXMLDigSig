package xmlsigmodule;

import org.w3c.dom.Document;



public class Test {

	/**
	 * 
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		
		
		String certCAfile = null; //CA's certificate file path.
		String certUserfile = null; //User's certificate file path.
		String cmtempfn = null; //CM template file name.
		String cminstfn = null; //CM instance file name.
		String cmtsignatureFN = null; //CM template signature file path.
		String absolutePath = null; //URI for both CM Template and Instance.
		String privKuser = null; //User private key file path.
		
		
		CMInstanceSignatureGenModule cmiSignature = new CMInstanceSignatureGenModule(certCAfile, certUserfile, cmtempfn, cminstfn, cmtsignatureFN, absolutePath, privKuser);
		
		
		
		Document signature = cmiSignature.sign();
		
	}
}