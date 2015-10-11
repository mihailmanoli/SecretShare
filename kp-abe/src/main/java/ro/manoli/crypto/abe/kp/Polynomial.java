package ro.manoli.crypto.abe.kp;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

/**
 * 
 * @author Mihail
 *
 */
public class Polynomial {
	private Element[] coefs;

	// generates a random polynomial of input degree where p(0) = zero_val
	public Polynomial(int degree, Element zero_val, Pairing pairing) {
		coefs = new Element[degree + 1];
		coefs[0] = zero_val.getImmutable();
		// Random random = new Random(System.currentTimeMillis());
		for (int i = 1; i <= degree; i++) {
			// coefs[i] = pairing.getG1().newRandomElement();
			// //pairing.getZr().newRandomElement();
			coefs[i] = pairing.getZr().newRandomElement().getImmutable();
		}
	}

	protected Element evaluate(Element x) {
		assert(coefs != null && coefs.length > 0);
		Element result = coefs[coefs.length - 1];

		for (int i = coefs.length - 2; i >= 0; i--) {
			result = result.mulZn(x);
			result = result.add(coefs[i]);
		}
		return result;
	}
}