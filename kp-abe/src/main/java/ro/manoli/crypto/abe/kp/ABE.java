package ro.manoli.crypto.abe.kp;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import it.unisa.dia.gas.jpbc.CurveGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.plaf.jpbc.pairing.CurveParams;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import java.util.ArrayList;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * 
 * @author Mihail
 *
 */
public class ABE {
	PublicParams publicParams;
	private Element y; // secret

	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();

		sb.append("publicParams: \n------------\n"); 
		sb.append(publicParams); 
		sb.append("\n------------\n");
		sb.append("Secret y = ");
		sb.append(y);

		return sb.toString();
	}

	public ABE(InputStream is) {
		publicParams = new PublicParams(is);
	}

	public void write(OutputStream os) {
		publicParams.write(os);
	}

	public ABE() {
		this(160, 512);
	}

	/**
	 * Constructor of ABE. Practically there is a part of the Setup algorithm
	 * of the KP-ABE in Large Universe construction. Here are set up public parameters:
	 * g - generator of bilinear group G1,
	 * y - the secret key,
	 * g1 - g^y,
	 * g2 - a random element of G2.
	 * @param rBits - the number of primes
	 * @param qBits - the bit length of each prime
	 */
	public ABE(int rBits, int qBits) {
		publicParams = new PublicParams();
		// Init the generator...
		// type A params are constructed on the curve y^2 = x^3 + x over the field F_q for some prime q = 3 mod 4.
		// both G1 and G2 are the group of points E(F_q), so this pairing is symmetric. 
		CurveGenerator curveGenerator = new TypeACurveGenerator(rBits, qBits);

		// Generate the parameters... let e : G1 X G1 -> G2 denote the bilinear map
		CurveParams curveParams = (CurveParams) curveGenerator.generate();
		publicParams.curveParams = curveParams;
		publicParams.pairing = PairingFactory.getPairing(curveParams);

		// let g be a generator of G1
		publicParams.g = publicParams.pairing.getG1().newRandomElement().getImmutable();
		// Choose a random value y in Zp
		// BigInteger q = curveParams.getBigInteger("q");
		// y = random(q); // master secret
		// y = new
		// BigInteger("5243908847495165305277382908302479893829445235410443979422877457286515717375779298009158571463797622138995453477912144123612939339529676151346809169867075");
		y = publicParams.pairing.getZr().newRandomElement();
		// y = publicParams.pairing.getG1().newRandomElement();
		// System.out.println("Master Secret=" + y);
		// let g1 = g^y.
		publicParams.g1 = publicParams.g.powZn(y).getImmutable();
		// Now choose a random element g2 of G1.
		publicParams.g2 = publicParams.pairing.getG1().newRandomElement().getImmutable();

		// BigInteger s = new
		// BigInteger("21306183723761491396096248625059748936328722866527613892031126634053286358307951798100467643013330609976650344857419319893620139052614863049965180049287984");
		// Element e = (publicParams.pairing.pairing(publicParams.g, publicParams.g2)).powZn(y.multiply(s));
	}

	public Entity getRootEntity() {
		if (y == null) // secret not present
			return null;
		Entity root = new Entity(y, this);
		y = null; // remove the secret for security reason as all the entities
				  // will have a ref to this object
		return root;
	}

	public byte[] encrypt(byte[] data, String[] attributes) {
		Ciphertext ct = enc(data, attributes);
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		ct.write(os);
		return os.toByteArray();
	}

	// attributes : atom , att=value , or #variable=constantInteger
	@SuppressWarnings("unchecked")
	private Ciphertext enc(byte[] message, String[] attributes) {
		ArrayList<String> attributesList = new ArrayList<String>();
		for (String att : attributes) {
			if (att.startsWith("#")) {
				String[] attrValue = att.substring(1).split("=", 2);
				if (attrValue != null) {
					try {
						int value = Integer.parseInt(attrValue[1]);
						Utility.addBitwiseAtts(attrValue[0], value, attributesList);
						continue;
					} catch (NumberFormatException nfe) {
						throw new RuntimeException(nfe);
					}
				}
			}
			attributesList.add(att);
		}

		attributes = attributesList.toArray(new String[0]);
		// choose a random value s in Zp
		// BigInteger q = publicParams.curveParams.getBigInteger("q");
		// BigInteger s = new
		// BigInteger("21306183723761491396096248625059748936328722866527613892031126634053286358307951798100467643013330609976650344857419319893620139052614863049965180049287984");
		Element s = publicParams.pairing.getZr().newRandomElement();
		// Element s = publicParams.pairing.getG1().newRandomElement();

		// BigInteger s = random(q);
		// System.out.println("s: " + s);

		Arrays.sort(attributes);

		Element g2s = publicParams.g.powZn(s).getImmutable();
		// Element g2s =
		// publicParams.g.powZn(publicParams.pairing.getZr().newElement(s)).getImmutable();
		// //.pow(s).getImmutable();

		// Element[] atts = new Element[attributes.length];
		Element[] eis = new Element[attributes.length];
		for (int i = 0; i < attributes.length; i++) {
			eis[i] = H1(attributes[i], publicParams.pairing.getG1()).powZn(s).getImmutable();
			// Eis[i] =
			// H1(attributes[i],publicParams.pairing.getG1()).powZn(publicParams.pairing.getZr().newElement(s)).getImmutable();
		}

		// e2s = e(g1,g2)^s
		Element e2s = publicParams.pairing.pairing(publicParams.g1, publicParams.g2).powZn(s).getImmutable();
		// Element e2s =
		// publicParams.pairing.pairing(publicParams.g1,publicParams.g2).powZn(publicParams.pairing.getZr().newElement(s)).getImmutable();

		// System.out.println("ecryption key : "+ e2s);
		byte[] key = H2(e2s);
		
		// FIXME do some testing here
		return new Ciphertext(attributes, g2s, eis, encryptAES(message, key));
	}
	
	static public BigInteger random(BigInteger limit) {
		Random random = new Random(System.currentTimeMillis());
		BigInteger n = BigInteger.ONE;
		do {
			String rand = (new Integer(random.nextInt(2147483647))).toString();
			n = n.multiply(new BigInteger(rand));
		} while (n.compareTo(limit) < 0);
		return n.mod(limit);
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
//			System.err.println("no such hash algorithm");
//			return null;
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
//			return null;
		}
	}

	private byte[] encryptAES(byte[] message, byte[] key) {
		byte[] cipherText = null;
		try {
			assert(key.length >= 16);
			// System.out.println("enc Key = " + new String(key));
			SecretKeySpec aes_key = new SecretKeySpec(key, 0, 16, "AES");
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, aes_key);

			// cipherText = new byte[cipher.getOutputSize(message.length)];
			// int ctLength = cipher.update(message, 0, message.length,
			// cipherText, 0);
			// ctLength += cipher.doFinal(cipherText, ctLength);
			cipherText = cipher.doFinal(message);
		} catch (Exception e) {
			throw new RuntimeException("failed to initialize cipher:", e);
		}

		return cipherText;
	}

	protected byte[] decryptAES(byte[] ciphertext, byte[] key) {
		// System.out.println("dec Key = " + new String(key));
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

	@SuppressWarnings("restriction")
	public boolean validateSignature(String[] atts, String message, String signature) {
		byte[] data = null;
		try {
			data = message.getBytes("UTF-8");
			return validateSignature(atts, data, new sun.misc.BASE64Decoder().decodeBuffer(signature));
		} catch (Exception e) {
			System.out.println("validateSignature:" + e);
			return false;
		}
	}

	@SuppressWarnings("restriction")
	public boolean validateSignature(String[] atts, byte[] data, byte[] signature) {
		boolean valid = false;

		Entity signatureEntity = new Entity(this, new ByteArrayInputStream(signature));
		String[] signatureEntityAtts = new String[atts.length + 1];
		System.arraycopy(atts, 0, signatureEntityAtts, 0, atts.length);
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA");
			md.update(data);
			signatureEntityAtts[atts.length] = "$sign_datahash=" + new sun.misc.BASE64Encoder().encode(md.digest()); // "$sign_datahash="
																														// +
																														// new
																														// String(md.digest(),"UTF-8");
			byte[] randomData = new byte[50];
			Random rnd = new Random();
			rnd.nextBytes(randomData);
			Ciphertext ct = this.enc(randomData, signatureEntityAtts);
			byte[] randomDataDec = signatureEntity.decrypt(ct);
			valid = Arrays.equals(randomData, randomDataDec);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

		return valid;
	}

	// extracts i bytes and put them in bytes starting at offset and ending at
	// offset+4
	public static void getIntegerBytes(int integer, byte[] bytes, int offset) {
		int i = 0;
		for (; i < 4; i++)
			bytes[offset++] = (byte) ((integer >> (i * 8)) & 0x000000FF);
	}

	// extract the integer stored at offset - offset+4
	public static int getIntegerFromBytes(byte[] bytes, int offset) {
		int integer = 0;
		int bias[] = new int[] { 256, 65536, 16777216, 0 };

		for (int i = 0; i < 4; i++) {
			int byteInt = (bytes[offset] << (i * 8));
			if (byteInt < 0)
				byteInt += bias[i];
			integer += byteInt;
			offset++;
		}
		return integer;
	}

	public static int readInteger(InputStream is) {
		int i = -1;
		byte[] bs = new byte[4];
		try {
			is.read(bs);
			i = getIntegerFromBytes(bs, 0);
		} catch (IOException exception) {
		}
		return i;
	}

	public static void writeInteger(int integer, OutputStream os) {
		byte[] bytes = new byte[4];
		getIntegerBytes(integer, bytes, 0);
		try {
			os.write(bytes);
		} catch (IOException exception) {
		}
	}
	
	static class PublicParams {
		CurveParams curveParams;
		Element g;
		Element g1;
		Element g2;

		Pairing pairing;

		PublicParams() {
		}

		PublicParams(InputStream is) {
			int len = readInteger(is);
			int offset = 0;
			// param len/param/g/g1/g2
			byte[] record = new byte[len];
			try {
				int a = is.available();
				int r = is.read(record);
				int paramLen = getIntegerFromBytes(record, offset);
				offset += 4;
				curveParams = new CurveParams();
				curveParams.load(new ByteArrayInputStream(record, offset, paramLen));
				offset += paramLen;
				pairing = PairingFactory.getPairing(curveParams);
				g = pairing.getG1().newElement();
				int i = g.setFromBytes(record, offset);
				offset += i;
				g = g.getImmutable();
				g1 = pairing.getG1().newElement();
				i = g1.setFromBytes(record, offset);
				offset += i;
				g1 = g1.getImmutable();
				g2 = pairing.getG1().newElement();
				i = g2.setFromBytes(record, offset);
				offset += i;
				g2 = g2.getImmutable();
			} catch (IOException e) {
				throw new RuntimeException("Error while creating public params", e);
			}
		}

		// rec len/param len/param/g/g1/g2
		public void write(OutputStream os) {
			try {
				int len = 0;
				byte[] curveParamBytes = curveParams.toString().getBytes("UTF-8");

				len += 4;
				len += curveParamBytes.length;
				len += g.getLengthInBytes();
				len += g1.getLengthInBytes();
				len += g2.getLengthInBytes();

				writeInteger(len, os);
				writeInteger(curveParamBytes.length, os);
				os.write(curveParamBytes);
				os.write(g.toBytes());
				os.write(g1.toBytes());
				os.write(g2.toBytes());
			} catch (UnsupportedEncodingException e) {
				throw new RuntimeException("Unsupported encoding ", e);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		@Override
		public String toString() {
			StringBuffer sb = new StringBuffer();

			sb.append(" curveParams: \n" + curveParams + "\n");
			sb.append("g = " + g + "\n");
			sb.append("g1 = " + g1 + "\n");
			sb.append("g2 = " + g2 + "\n");

			return sb.toString();
		}
	}

}
