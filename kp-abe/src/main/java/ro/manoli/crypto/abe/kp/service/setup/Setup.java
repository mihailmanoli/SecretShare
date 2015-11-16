package ro.manoli.crypto.abe.kp.service.setup;

import java.io.Serializable;

import it.unisa.dia.gas.jpbc.CurveGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.pairing.CurveParams;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

/**
 * 
 * @author Mihail
 *
 */
public class Setup implements Serializable {
	private static final long serialVersionUID = 1L;

	public PublicParams publicParams;
	// secret
	private Element y; 
	
	private PkParams pkParams;
	private Element[] masterKey;
	
	public Setup() {
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
	public Setup(int primeNumbers, int primesSize) {
		this.publicParams = new PublicParams();
		// Init the generator...
		// type A params are constructed on the curve y^2 = x^3 + x over the field F_q for some prime q = 3 mod 4.
		// both G1 and G2 are the group of points E(F_q), so this pairing is symmetric. 
		CurveGenerator curveGenerator = new TypeACurveGenerator(primeNumbers, primesSize);
		
		// Generate the parameters... let e : G1 X G1 -> G2 denote the bilinear map.
		publicParams.setCurveParams((CurveParams) curveGenerator.generate());
		
		publicParams.setPairing(PairingFactory.getPairing(publicParams.getCurveParams()));
		
		publicParams.setG(publicParams.getPairing().getG1().newRandomElement().getImmutable());
		
		this.y = publicParams.getPairing().getZr().newRandomElement();
		
		// TODO s-ar putea sa mai avem nevoie de niste initializari
	}
	
	public void generateMasterKey(String[] attributes) {
		int attributesLength = attributes.length;
		
		Element[] ti = new Element[attributesLength];
		Element local_y;
		for(int i = 0; i < attributesLength; i++) {
			Element randomTi = publicParams.getPairing().getZr().newRandomElement();
			ti[i] = this.publicParams.getG().powZn(randomTi);
		}
		local_y = publicParams.getPairing().pairing(publicParams.getG(), publicParams.getG()).powZn(this.y).getImmutable();
		pkParams = new PkParams(ti, local_y);
		
		this.masterKey = new Element[attributesLength + 1];
		System.arraycopy(ti, 0, masterKey, 0, attributesLength);
		
		this.masterKey[attributesLength] = local_y;
	}
	
	public PkParams getPkParams() {
		return pkParams;
	}
	
//	public byte[] getMasterKey() throws IOException {
//		ByteArrayOutputStream bos = new ByteArrayOutputStream();
//	    ObjectOutputStream oos = new ObjectOutputStream(bos);
//	    oos.writeObject(masterKey);
//	    return bos.toByteArray();
//	}
}
