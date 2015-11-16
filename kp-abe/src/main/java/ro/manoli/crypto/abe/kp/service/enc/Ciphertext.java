package ro.manoli.crypto.abe.kp.service.enc;

import it.unisa.dia.gas.jpbc.Element;

/**
 * 
 * @author Mihail
 *
 */
public class Ciphertext {
	private String[] attributes;
	private byte[] encryptedMessage;
	private Element[] eis;
	
	public Ciphertext(String[] attributes, byte[] encryptedMessage, Element[] eis) {
		this.attributes = attributes;
		this.encryptedMessage = encryptedMessage;
		this.eis = eis;
	}
	
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();

		sb.append("Attributes: \n");
		for (String att : attributes) {
			sb.append(att + "\n");
		}
		sb.append("Eis: \n");
		for (Element e : eis) {
			sb.append("" + e + "\n");
		}
		sb.append("Size of encrypted data = " + encryptedMessage.length);

		return sb.toString();
	}
	
	//TODO de gandit un mod cum sa construim un byte[] din criptotext
}
