package ro.manoli.crypto.abe.kp.service.setup;

import it.unisa.dia.gas.jpbc.Element;

/**
 * 
 * @author Mihail
 *
 */
public class PkParams {
	public Element[] ti;
	
	private Element y;
	
	public PkParams() {
	}

	public PkParams(Element[] ti, Element y) {
		this.ti = ti;
		this.y = y;
	}
	
	public Element[] getTi() {
		return ti;
	}
	
	public void setTi(Element[] ti) {
		this.ti = ti;
	}
	
	public Element getY() {
		return y;
	}
	
	public void setY(Element y) {
		this.y = y;
	}
}
