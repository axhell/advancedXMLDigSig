package xmlsigcore;
import java.io.IOException;
import java.io.InputStream;

import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignatureFactory;


/**
 * URI dereferencer for <Reference> without a URI attribute. It will fall back to
 * default for all other references with a URI.
 * <p>
 * According to <code>URIDereferencer</code> documentation,
 * <code>OctetStreamData</code> should be returned from <code>dereference</code>
 * method.
 * </p>
 */
public class MyURIDereferencer implements URIDereferencer
	{
	    private InputStream inputStream;

	    public MyURIDereferencer(InputStream inputStream) throws IOException
	    {
	        this.inputStream = inputStream;
	    }

	    public Data dereference(URIReference uriReference, XMLCryptoContext context)
	        throws URIReferenceException
	    {
	        if (uriReference.getURI() == null)
	        {
	            Data data = new OctetStreamData(this.inputStream);
	            return data;
	        }
	        else
	        {
	            URIDereferencer defaultDereferencer = XMLSignatureFactory.getInstance("DOM").
	                getURIDereferencer();
	            return defaultDereferencer.dereference(uriReference, context);
	        }
	    }
	}    

