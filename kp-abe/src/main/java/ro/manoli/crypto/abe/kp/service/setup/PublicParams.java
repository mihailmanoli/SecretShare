package ro.manoli.crypto.abe.kp.service.setup;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.CurveParams;

/**
 * 
 * @author Mihail
 *
 */
public class PublicParams {
	private CurveParams curveParams;
	private Element g;
	private Element g1;
	private Element g2;
	
	private Pairing pairing;
	
	public PublicParams() {
	}
	
	public CurveParams getCurveParams() {
		return curveParams;
	}
	
	public void setCurveParams(CurveParams curveParams) {
		this.curveParams = curveParams;
	}
	
	public Element getG() {
		return g;
	}
	
	public void setG(Element g) {
		this.g = g;
	}
	
	public Element getG1() {
		return g1;
	}
	
	public void setG1(Element g1) {
		this.g1 = g1;
	}
	
	public Element getG2() {
		return g2;
	}
	
	public void setG2(Element g2) {
		this.g2 = g2;
	}
	
	public Pairing getPairing() {
		return pairing;
	}
	
	public void setPairing(Pairing pairing) {
		this.pairing = pairing;
	}
}
