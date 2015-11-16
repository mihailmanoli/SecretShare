package ro.manoli.crypto.abe.kp;

/**
 * 
 * @author Mihail
 *
 */
public class StartABE {
	public static void main(String[] args) {
		ABE abe = new ABE();
		System.out.println("abe" + abe);
		try {
			Entity root = abe.getRootEntity();
			System.out.println("" + root);

			byte[] c = "Mihail".getBytes();
			String s = root.sign("Mihail");
			System.out.println("Valid = " + abe.validateSignature(new String[] { "#level1N=14", "l1=a" }, "Mihail", s));

			byte[] ciphertext = abe.encrypt(c, new String[] { "a", "b", "c", "level1=A", "level2=B", "level3=C",
					"level4=D", "#level1N=10", "#level2N=3", "#level3N=1", "#level4N=5" });
			byte[] data = root.decrypt(ciphertext);
			
			assert c == data;
			
			Entity manager = root.derive("(and (< level1N 13) b)"); 
			String signature = manager.sign("Mihail");
			System.out.println("Valid = " + abe.validateSignature(new String[] { "#level1N=14" }, "Mihail", signature));
		} catch (ExpresionException we) {
			throw new RuntimeException(we);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
