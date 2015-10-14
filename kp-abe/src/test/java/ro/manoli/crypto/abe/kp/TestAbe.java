package ro.manoli.crypto.abe.kp;

import java.io.UnsupportedEncodingException;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author Mihail
 *
 */
public class TestAbe {
	private ABE abe;
	
	@Before
	public void init() {
		abe = new ABE();
	}
	
	@After
	public void clear() {
		abe = null;
	}
	
	@Test
	public void testEncryptionDecryption() throws UnsupportedEncodingException {
		String dataToEcrypt = "test data";
		byte[] data = dataToEcrypt.getBytes();
		String[] attrs = new String[] { "a", "b", "c" };
		byte[] cipertext = abe.encrypt(data, attrs);
		System.out.println("cipertext: " + cipertext);
		
		Entity root = abe.getRootEntity();
		System.out.println("root: " + root);
		
		byte[] result = root.decrypt(cipertext);
		System.out.println("result: " + result);
		
		String decriptedData = new String(result, "UTF-8");
		Assert.assertEquals(dataToEcrypt, decriptedData);
	}

	@Test
	public void testSigning() {
		Entity root = abe.getRootEntity();
		String signature = root.sign("test data");
		
		boolean isValid = abe.validateSignature(new String[] {"attr1", "attr2", "attr3" }, "test data", signature);
		
		Assert.assertEquals(true, isValid);
	}

	@Test
	public void testSigningOnOtherLevel() throws ExpresionException {
		String message = "test data";

		Entity root = abe.getRootEntity();
		String signature = root.sign(message);
		
		boolean isValid = abe.validateSignature(new String[] {"attr1", "attr2", "attr3" }, message, signature);
		Assert.assertEquals(true, isValid);
		
		Entity manager = root.derive("(and (< level1N 13))");
		String managerSignature = manager.sign(message);
		
		boolean isNewSigningValid = abe.validateSignature(new String[] {"attr1"}, message, managerSignature);
		Assert.assertEquals(false, isNewSigningValid);
	}
	
	@Test
	public void testEncryptionDecryptionPerformance() throws UnsupportedEncodingException {
		String dataToEcrypt = "test data";
		byte[] data = dataToEcrypt.getBytes();
		String[] attrs = new String[] { "a", "b", "c" };
		byte[] cipertext = abe.encrypt(data, attrs);
		System.out.println("cipertext: " + cipertext);
		
		Entity root = abe.getRootEntity();
		System.out.println("root: " + root);
		
		byte[] result = root.decrypt(cipertext);
		System.out.println("result: " + result);
		
		String decriptedData = new String(result, "UTF-8");
		Assert.assertEquals(dataToEcrypt, decriptedData);
	}
}
