
import java.security.*;
import java.util.*;

import javax.xml.crypto.dsig.*;

public class XMLSignatureOptionSelector {
		
	
		XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM"); 
		PublicKey pubkey;
		PrivateKey privkay;
		List<Reference> refs = new ArrayList<Reference>();
		String sigType;
		SignatureMethod sigMethod;//algorithm of the key
		String transformMethod;
		
		private void test(){
			
		}
}
