package ro.manoli.crypto.abe.kp;

import java.io.OutputStream;
import java.io.InputStream;
import java.io.IOException;

import it.unisa.dia.gas.jpbc.Element;

public class Ciphertext {
	String[] atts;
	Element g2s;
	Element[] eis;
	byte[] enc;

	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();

		sb.append("Attributes: \n");
		for (String att : atts) {
			sb.append(att + "\n");
		}
		sb.append("\ng2s = " + g2s + "\n");
		sb.append("Eis: \n");
		for (Element e : eis) {
			sb.append("" + e + "\n");
		}
		sb.append("Size of encrypted data = " + enc.length);

		return sb.toString();
	}

	// rec len, enc len , REC:(atts len, (att len, att), g2s , Eis len, Eis),
	// enc bytes
	/**
	 * Asociem criptotextul cu atributele
	 */
	public Ciphertext(ABE abe, InputStream is) {
		int len = ABE.readInteger(is);
		int encLen = ABE.readInteger(is);

		byte[] record = new byte[len];
		try {
			is.read(record);
			int offset = 0;

			int attsLen = ABE.getIntegerFromBytes(record, offset);
			offset += 4;
			atts = new String[attsLen];
			for (int i = 0; i < attsLen; i++) {
				int attLen = ABE.getIntegerFromBytes(record, offset);
				offset += 4;
				atts[i] = new String(record, offset, attLen, "UTF-8");
				offset += attLen;
			}
			g2s = abe.publicParams.pairing.getG1().newElement();
			offset += g2s.setFromBytes(record, offset);
			g2s = g2s.getImmutable();
			int EisLen = ABE.getIntegerFromBytes(record, offset);
			offset += 4;
			eis = new Element[EisLen];
			for (int i = 0; i < EisLen; i++) {
				eis[i] = abe.publicParams.pairing.getG1().newElement();
				offset += eis[i].setFromBytes(record, offset);
				eis[i] = eis[i].getImmutable();
			}
			enc = new byte[encLen];
			is.read(enc);

		} catch (IOException e) {
			throw new RuntimeException("Chipertext: ", e);
		}
	}

	Ciphertext(String[] atts, Element g2s, Element[] Eis, byte[] enc) {
		this.atts = atts;
		this.g2s = g2s;
		this.eis = Eis;
		this.enc = enc;
	}

	public void write(OutputStream os) {
		// rec len, atts len, atts, g2s , Eis len, Eis, enc len , enc bytes
		// rec len, enc len , REC:(atts len, (att len, att), g2s , Eis len,
		// Eis), enc bytes
		int len = 0;
		len += 4;
		byte[][] attsBytes = new byte[atts.length][];
		for (int i = 0; i < atts.length; i++) {
			try {
				attsBytes[i] = atts[i].getBytes("UTF-8");
				len += attsBytes[i].length;
				len += 4;
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		}

		len += g2s.getLengthInBytes();
		len += 4;
		for (int i = 0; i < eis.length; i++) {
			len += eis[i].getLengthInBytes();
		}

		ABE.writeInteger(len, os);
		ABE.writeInteger(enc.length, os);

		ABE.writeInteger(atts.length, os);
		for (int i = 0; i < atts.length; i++) {
			try {
				ABE.writeInteger(attsBytes[i].length, os);
				os.write(attsBytes[i]);
			} catch (IOException e) {
				System.out.println("Cipeertext write:" + e);
			}
		}
		try {
			os.write(g2s.toBytes());
		} catch (IOException e) {
			System.out.println("Cipeertext write, g2s :" + e);
		}
		ABE.writeInteger(eis.length, os);
		for (int i = 0; i < eis.length; i++) {
			try {
				os.write(eis[i].toBytes());
			} catch (IOException e) {
				System.out.println("Cipeertext write:" + e);
			}
		}
		try {
			os.write(enc);
		} catch (IOException e) {
			System.out.println("Cipeertext write, enc :" + e);
		}
	}

}
