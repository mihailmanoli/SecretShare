package ro.manoli.crypto.abe.kp.service;

import ro.manoli.crypto.abe.kp.service.setup.Setup;

/**
 * 
 * @author Mihail
 *
 */
public class AbeInit {
	
	public static void main(String[] args) {
		Setup setup = new Setup();
		String[] attributes = new String[] { "manager", "sofer" };
		setup.generateMasterKey(attributes);
	}
}
