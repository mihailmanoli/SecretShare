package ro.manoli.crypto.abe.kp.service.enc;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import ro.manoli.crypto.abe.kp.service.setup.PkParams;
import ro.manoli.crypto.abe.kp.service.setup.PublicParams;

/**
 * 
 * @author Mihail
 *
 */
public class Encryption {
	public Element s;
	
	public Encryption() {
	}
	
	@SuppressWarnings("unchecked")
	public Ciphertext encryptMessage(byte[] message, String[] attributes, PublicParams publicParams, PkParams pkParams) {
		
		// TODO de vazut cum se poate fixa atributele in arborele [0,1]
		
		Arrays.sort(attributes);

		this.s = publicParams.getPairing().getZr().newRandomElement();
		
		Element[] eis = new Element[attributes.length];
		for(int i = 0; i < attributes.length; i++) {
			eis[i] = H1(attributes[i], publicParams.getPairing().getG1()).powZn(s).getImmutable();
		}
		
		Element y2s = pkParams.getY().powZn(s).getImmutable();
		byte[] key = H2(y2s);
		
		return new Ciphertext(attributes, encryptAES(message, key), eis);
	}
	
	public Element getS() {
		return s;
	}
	
	// H1 : {0,1}* -> G1
	public static Element H1(String string, Field<Element> G1) {
		// Generate an hash from string (48-bit hash)
		try {
			MessageDigest md = MessageDigest.getInstance("SHA");
			byte[] bytes = null;
			try {
				bytes = string.getBytes("UTF-8");
			} catch (UnsupportedEncodingException e) {
				throw new RuntimeException(e);
			}

			md.update(bytes);
			byte[] hash = md.digest();
			Element h = G1.newElement().setFromHash(hash, 0, hash.length);
			return h;
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("No such hash algorith", e);
		}
	}

	// H2 : G2 -> {0,1}n
	byte[] H2(Element element) {
		// Generate an hash from string (48-bit hash)
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA");
			md.update(element.toBytes());
			return md.digest();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("No such hash algorith", e);
		}
	}

	private byte[] encryptAES(byte[] message, byte[] key) {
		byte[] cipherText = null;
		try {
			assert(key.length >= 16);
			
			SecretKeySpec aes_key = new SecretKeySpec(key, 0, 16, "AES");
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, aes_key);

			cipherText = cipher.doFinal(message);
		} catch (Exception e) {
			throw new RuntimeException("failed to initialize cipher:", e);
		}
		return cipherText;
	}

	protected byte[] decryptAES(byte[] ciphertext, byte[] key) {
		byte[] plaintext = null;
		try {
			assert(key.length >= 16);
			SecretKeySpec aes_key = new SecretKeySpec(key, 0, 16, "AES");

			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, aes_key);

			plaintext = cipher.doFinal(ciphertext);
		} catch (Exception e) {
			throw new RuntimeException("failed to initialize cipher:", e);
		}
		return plaintext;
	}
}
