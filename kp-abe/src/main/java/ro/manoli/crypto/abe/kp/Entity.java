package ro.manoli.crypto.abe.kp;

import de.tudresden.inf.lat.jsexp.Sexp;
import de.tudresden.inf.lat.jsexp.SexpFactory;
import it.unisa.dia.gas.jpbc.Element;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;

/**
 * 
 * @author Mihail
 *
 */
public class Entity {
	private Sexp accessTree;
	private Element[] Dis;
	private Element[] Ris;
	private int currentDis_Ris_Index = -1;
	private ABE abe;
	private Boolean isRoot;
	// BigInteger secret; // y --> only if the root Entity (in that case the
	// rest excep abe is null
	private Element secret;

	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();

		if (isRoot) {
			sb.append("ROOT entity\n");
			sb.append("Secret = " + secret);
		} else {
			sb.append("AccessTree: \n");
			sb.append("" + accessTree);
			sb.append("\nDis:\n");
			for (Element di : Dis) {
				sb.append(di + "\n");
			}
			sb.append("\nRis:\n");
			for (Element ri : Ris) {
				sb.append(ri + "\n");
			}
		}
		sb.append("\nABE params:\n " + abe);

		return sb.toString();
	}

	// constructor for root Entity
	public Entity(Element secret, ABE abe) {
		this.secret = secret;
		this.abe = abe;
		isRoot = true;
	}

	public Entity(ABE abe, InputStream is) {
		this.abe = abe;
		int len = ABE.readInteger(is);
		byte[] record = new byte[len];
		try {
			is.read(record);
			// len, (is root 1) secret
			if (record[0] == 1) {
				// root
				isRoot = true;
				secret = abe.publicParams.pairing.getZr().newElement();
				secret.setFromBytes(record, 1);
				secret = secret.getImmutable();
			} else {
				// len, (is root 0) , len Dis, Dis, len Ris, Ris, tree len ,
				// tree
				isRoot = false;
				int offset = 1;
				int DisLen = ABE.getIntegerFromBytes(record, offset);
				offset += 4;
				Dis = new Element[DisLen];
				for (int i = 0; i < DisLen; i++) {
					Dis[i] = abe.publicParams.pairing.getG1().newElement();
					offset += Dis[i].setFromBytes(record, offset);
					Dis[i] = Dis[i].getImmutable();
				}
				int RisLen = ABE.getIntegerFromBytes(record, offset);
				offset += 4;
				Ris = new Element[RisLen];
				for (int i = 0; i < RisLen; i++) {
					Ris[i] = abe.publicParams.pairing.getG1().newElement();
					offset += Ris[i].setFromBytes(record, offset);
					Ris[i] = Ris[i].getImmutable();
				}
				int treeLen = ABE.getIntegerFromBytes(record, offset);
				offset += 4;
				String treeExp = "";

				treeExp = new String(record, offset, treeLen, "UTF-8");
				accessTree = SexpFactory.parse(treeExp);
			}
		} catch (Exception e) {
			throw new RuntimeException("Entity constructor:", e);
		}

	}

	public Entity(Sexp accessTree, Element[] Dis, Element[] Ris, ABE abe) { // if
																		// accessTree
																		// = ""
																		// &&
																		// Dis.len
																		// = 1
																		// &&
																		// Ris.len
																		// = 0
																		// ==>
																		// represents
																		// the
																		// root
																		// entity
		this.accessTree = accessTree;
		this.Dis = Dis;
		this.Ris = Ris;
		this.abe = abe;
		this.isRoot = false;

	}

	public Entity derive(String sExpresion) throws ExpresionException {
		Entity derivedEntity = null;
		Sexp derivedAccessTree = null;
		List<Element> derivedDis = new ArrayList<Element>();
		List<Element> derivedRis = new ArrayList<Element>();
		Sexp existingAccessTree = null;

		// BigInteger zeroValue = null;
		Element zeroValue = null;

		if ( ! isRoot) {
			try {
				existingAccessTree = SexpFactory.parse(accessTree.toString());
			} catch (Exception e) {
				throw new ExpresionException("unable to parse " + accessTree.toString());
			}

			if ( ! isRootAnd(existingAccessTree)) {
				// add an and node to the root
				Sexp andRoot = SexpFactory.newNonAtomicSexp();
				andRoot.add(SexpFactory.newAtomicSexp("1"));
				andRoot.add(existingAccessTree);
				existingAccessTree = andRoot;
			}
			int i_v = existingAccessTree.getLength();
			// Element v =
			// abe.publicParams.pairing.getG1().newElement(i_v).getImmutable();
			// Element v =
			// abe.publicParams.pairing.getG1().newElement(BigInteger.valueOf(i_v)).getImmutable();
			Element v = abe.publicParams.pairing.getZr().newElement(-1 * i_v); // .newOneElement().mul(BigInteger.valueOf(i_v)).getImmutable();

			Element a = v.invert().getImmutable();

			int k = 0;
			for (int i = 1; i < existingAccessTree.getLength(); i++) {
				// Cx = a.index(y) + 1
				Element C = (a.mul(abe.publicParams.pairing.getZr().newElement(i))
						.add(abe.publicParams.pairing.getZr().newOneElement())).getImmutable();

				int n = nTerminal(existingAccessTree.get(i));
				for (int j = 0; j < n; j++) {
					Element newDi = Dis[k].powZn(C).getImmutable();
					Element newRi = Ris[k].powZn(C).getImmutable();

					derivedDis.add(newDi);
					derivedRis.add(newRi);
					k++;
				}
			}

			zeroValue = abe.publicParams.pairing.getZr().newZeroElement();

		} else {
			// not implemented yet!!!
			// zeroValue = abe.publicParams.pairing.getG1().newElement(secret);
			zeroValue = (secret);
		}

		Sexp newExpr = null;

		try {
			newExpr = SexpFactory.parse(sExpresion);
		} catch (Exception e) {
			throw new ExpresionException("unable to parse " + sExpresion);
		}

		newExpr = preprocess(newExpr); // replace numerical comparison with
										// symbolic matching

		leafAssignment(newExpr, zeroValue, derivedDis, derivedRis);

		if (isRoot) // RootEntity
		{
			derivedAccessTree = newExpr;
		} else // add it to the AND rooted tree existingAccessTree
		{
			/*
			 * String threshold = existingAccessTree.get(0).toString(); int t =
			 * 0; try { t = Integer.parseInt(threshold.toString());
			 * }catch(NumberFormatException e) { new WrongExpresion(
			 * "first item should be and/or/number :" + threshold); }
			 */
			int t = getThreshold(existingAccessTree);
			if (t <= 0)
				throw new ExpresionException("first item should be and/or/number :" + existingAccessTree);

			derivedAccessTree = SexpFactory.newNonAtomicSexp();
			derivedAccessTree.add(SexpFactory.newAtomicSexp("" + ++t));
			for (int i = 1; i < existingAccessTree.getLength(); i++) {
				derivedAccessTree.add(existingAccessTree.get(i));
			}
			derivedAccessTree.add(newExpr);
		}
		derivedEntity = new Entity(derivedAccessTree, derivedDis.toArray(new Element[0]),
				derivedRis.toArray(new Element[0]), abe);
		return derivedEntity;
	}

	private Sexp preprocess(Sexp expr) throws ExpresionException {
		if (expr.isAtomic())
			return expr;
		else if (isNumericalComparision(expr))
			return convertToSymbolicMatch(expr);
		else {
			// (threshold expr1 expr2 ... exprn)
			Sexp processedExpr = SexpFactory.newNonAtomicSexp();

			if (isValidThreshold("" + expr.get(0))) {
				processedExpr.add(expr.get(0));
			} else {
				throw new ExpresionException(expr.get(0) + " is not a valid threshold!");
			}

			for (int i = 1; i < expr.getLength(); i++) {
				Sexp result = preprocess(expr.get(i));
				processedExpr.add(result);
			}
			return processedExpr;
		}
	}

	private Sexp convertToSymbolicMatch(Sexp expr) {
		Sexp result = null;
		String operator = "" + expr.get(0);
		String oprand1 = "" + expr.get(1);
		String oprand2 = "" + expr.get(2);

		if (Utility.isIntNumber(oprand1))
			if (operator.equals("<")) {
				result = Utility.lt(oprand1, oprand2);
			} else {
				result = Utility.gt(oprand1, oprand2);
			}
		else {
			if (operator.equals("<")) {
				result = Utility.gt(oprand2, oprand1);
			} else {
				result = Utility.lt(oprand2, oprand1);
			}
		}
		return result;
	}

	private boolean isNumericalComparision(Sexp expr) throws ExpresionException {
		boolean result = false;
		if (!expr.isAtomic() && expr.getLength() == 3 && expr.get(0).isAtomic()) {
			String oper = "" + expr.get(0);
			if (oper.equals(">") || oper.equals("<")) {
				if (expr.get(1).isAtomic() && expr.get(2).isAtomic()) {
					if (Utility.isIntNumber("" + expr.get(1)) || Utility.isIntNumber("" + expr.get(2))) {
						result = true;
					}
				} else {
					throw new ExpresionException(
							"One of the comparison oprands should be constant int : " + expr.get(1) + expr.get(2));
				}
			}
		}
		return result;
	}

	private boolean isValidThreshold(String t) {
		boolean result = false;
		if (t.toLowerCase().equals("and") || t.toLowerCase().equals("or") || Utility.isIntNumber(t))
			result = true;

		return result;
	}

	@SuppressWarnings("unchecked")
	private void leafAssignment(Sexp exp, Element zeroValue, List<Element> Dis, List<Element> Ris) {
		// System.out.println("p(0) at " + exp + " = " + zeroValue);
		// BigInteger q = abe.publicParams.curveParams.getBigInteger("q");

		if (exp.isAtomic()) {
			// BigInteger r = ABE.random(q);
			Element r = abe.publicParams.pairing.getZr().newRandomElement();
			// Element rz = abe.publicParams.pairing.getZr().newElement(r);
			// Element g22z = abe.publicParams.g2
			// E.pow(zeroValue);

			Element g22z = abe.publicParams.g2.powZn(zeroValue);
			// Element g22z = abe.publicParams.g2.pow(zeroValue);

			// Element Di = g22z.mul(ABE.H1(exp.toString(),
			// abe.publicParams.pairing.getG1()).pow(r));
			Element Di = g22z.mul(ABE.H1(exp.toString(), abe.publicParams.pairing.getG1()).powZn(r));

			Dis.add(Di.getImmutable());
			Element Ri = abe.publicParams.g.powZn(r);
			Ris.add(Ri.getImmutable());

			return;
		}
		Polynomial p = new Polynomial(getThreshold(exp) - 1, zeroValue, abe.publicParams.pairing);
		for (int i = 1; i < exp.getLength(); i++) {
			leafAssignment(exp.get(i), p.evaluate(abe.publicParams.pairing.getZr().newElement(i)), Dis, Ris);
			// leafAssignment(exp.get(i),p.evaluate(i-1),Dis,Ris);
		}
	}

	private int nTerminal(Sexp exp) {
		if (exp.isAtomic())
			return 1;
		int c = 0;
		for (int i = 1; i < exp.getLength(); i++) {
			c += nTerminal(exp.get(i));
		}
		return c;
	}

	private boolean isRootAnd(Sexp sexp) throws ExpresionException {
		boolean result = false;
		Sexp threshold = sexp.get(0);
		if (!threshold.isAtomic())
			throw new ExpresionException("first item should be atomic");
		if (threshold.toString().toLowerCase().equals("and"))
			result = true;
		else {
			int t = 0;
			try {
				t = Integer.parseInt(threshold.toString());
			} catch (NumberFormatException e) {
				new ExpresionException("first item should be and/or/number :" + threshold);
			}
			result = (t == sexp.getLength() - 1);

		}
		return result;
	}

	// \Delta_{i,S(x)} = P_{j in S, j<>i}(0-j)/(i-j)
	private Element lagrange(int[] S, int i) {
		// Element dividend = abe.publicParams.pairing.getG1().newOneElement();
		// Element divisor = abe.publicParams.pairing.getG1().newOneElement();
		Element dividend = abe.publicParams.pairing.getZr().newOneElement();
		Element divisor = abe.publicParams.pairing.getZr().newOneElement();
		int j;
		for (int k = 0; k < S.length; k++) {
			j = S[k];
			if (j == i)
				continue;
			dividend = dividend.mulZn(abe.publicParams.pairing.getZr().newElement(-j));
			divisor = divisor.mulZn(abe.publicParams.pairing.getZr().newElement(i - j));
		}
		Element l = dividend.div(divisor);

		// l = l.mod(abe.publicParams.curveParams.getBigInteger("q"));
		return l;
	}

	public byte[] decrypt(byte[] ciphertext) {
		return decrypt(new Ciphertext(abe, new ByteArrayInputStream(ciphertext)));
	}

	public byte[] encrypt(byte[] data, String[] attributes) {
		return abe.encrypt(data, attributes);
	}

	@SuppressWarnings("restriction")
	public String sign(String message) {
		byte[] signature = null;
		try {
			signature = sign(message.getBytes("UTF-8"));
		} catch (Exception e) {
		}
		return new sun.misc.BASE64Encoder().encode(signature);
	}

	@SuppressWarnings("restriction")
	public byte[] sign(byte[] data) {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		try {
			MessageDigest md = null;
			try {
				md = MessageDigest.getInstance("SHA");
				md.update(data);
				Entity e = derive("$sign_datahash=" + new sun.misc.BASE64Encoder().encode(md.digest())); // new
																											// String(md.digest(),"UTF-8")).write(os);
				e.write(os);
			} catch (NoSuchAlgorithmException e) {
				return null;
			}

		} catch (Exception e) {
			System.out.println("sign: " + e);
		}
		return os.toByteArray();
	}

	public byte[] decrypt(Ciphertext ciphertext) {
		byte[] text = null;
		currentDis_Ris_Index = 0;
		Element e2s = null;
		if (isRoot) {
			e2s = abe.publicParams.pairing.pairing(ciphertext.g2s, abe.publicParams.g2).powZn(this.secret)
					.getImmutable();
		} else {
			e2s = decryptNode(accessTree, ciphertext.eis, ciphertext.g2s, ciphertext.atts);
		}

		if (e2s != null) {
			// System.out.println("decryption key : "+ e2s);
			byte[] key = abe.H2(e2s);
			text = abe.decryptAES(ciphertext.enc, key);
		} else {
			// System.out.println("e2s is null!");
		}

		return text;
	}

	private Element decryptNode(Sexp accessTree, Element[] Eis, Element g2s, String[] attributes) {
		Element result = null;
		if (accessTree.isAtomic()) {
			result = decryptNodeLeaf(accessTree.toString(), Eis, g2s, attributes);
		} else {
			result = decryptInternalNode(accessTree, Eis, g2s, attributes);
		}

		return result;
	}

	private Element decryptNodeLeaf(String attribute, Element[] Eis, Element g2s, String[] attributes) {
		int index = java.util.Arrays.binarySearch(attributes, attribute);
		if (index < 0) {
			this.currentDis_Ris_Index++;
			return null;
		}
		Element e1 = abe.publicParams.pairing.pairing(Dis[currentDis_Ris_Index], g2s).getImmutable();
		Element e2 = abe.publicParams.pairing.pairing(Ris[currentDis_Ris_Index], Eis[index]).getImmutable();
		this.currentDis_Ris_Index++;

		Element r = e1.div(e2);

		// BigInteger s = new
		// BigInteger("21306183723761491396096248625059748936328722866527613892031126634053286358307951798100467643013330609976650344857419319893620139052614863049965180049287984");
		// BigInteger y = new
		// BigInteger("5243908847495165305277382908302479893829445235410443979422877457286515717375779298009158571463797622138995453477912144123612939339529676151346809169867075");
		// Element rp =
		// abe.publicParams.pairing.pairing(abe.publicParams.g,abe.publicParams.g2).pow(s.multiply(y));
		return r;
	}

	private Element decryptInternalNode(Sexp accessTree, Element[] Eis, Element g2s, String[] attributes) {
		int t = getThreshold(accessTree);
		Element result = null;
		if (t > 0) {
			int satisfied = 0;
			int i = 1;
			Element[] Fzs = new Element[t];
			int[] Sp = new int[t];
			// int k =0;
			while (satisfied < t && (accessTree.getLength() - i) >= (t - satisfied)) {
				Element r = decryptNode(accessTree.get(i), Eis, g2s, attributes);
				if (r != null) {
					Sp[satisfied] = i;
					Fzs[satisfied] = r;

					satisfied++;
				}
				i++;
			}
			// skip private elements corresponding to the rest of unprocessed
			// nodes
			for (; i < accessTree.getLength(); i++)
				this.currentDis_Ris_Index += countAtomics(accessTree.get(i));
			
			if (satisfied == t) {
				Element PI = abe.publicParams.pairing.getGT().newOneElement();
				// Element PI =
				// abe.publicParams.pairing.getZr().newOneElement();

				for (int j = 0; j < t; j++) {
					Element l = lagrange(Sp, Sp[j]);
					// System.out.println("L("+Sp[j]+")= " + l);

					// Element p = Fzs[j].pow(l);
					// l =
					// l.mod(abe.publicParams.curveParams.getBigInteger("q"));
					// System.out.println("moded! : " + l);
					// System.out.println("Zred ! : " +
					// abe.publicParams.pairing.getZr().newElement(l));
					// Element p = Fzs[j].pow(l); //
					// Fzs[j].powZn(abe.publicParams.pairing.getZr().newElement(l));
					Element p = Fzs[j].powZn(l);

					PI.mul(p);
					// PI.mulZn(p);
				}
				result = PI;
			}
		}
		return result;
	}

	private int countAtomics(Sexp tree) {
		if (tree.isAtomic())
			return 1;
		else {
			int c = 0;
			for (int i = 1; i < tree.getLength(); i++)
				c += countAtomics(tree.get(i));
			return c;
		}
	}

	private int getThreshold(Sexp accessTree) {
		int threshold = -1;
		Sexp t_exp = accessTree.get(0);
		if (t_exp.isAtomic()) {
			if (t_exp.toString().toLowerCase().equals("and"))
				threshold = accessTree.getLength() - 1;
			else if (t_exp.toString().toLowerCase().equals("or"))
				threshold = 1;
			else {
				try {
					threshold = Integer.parseInt(t_exp.toString());
				} catch (NumberFormatException e) {
					throw new RuntimeException(e);
				}
			}
		}
		return threshold;
	}

	public void write(OutputStream os) {
		try {
			// abe.write(os);
			int recordLen = 0;
			// len, (is root 1) secret
			if (isRoot) {
				recordLen++;
				recordLen += secret.getLengthInBytes();
				ABE.writeInteger(recordLen, os);
				os.write(new byte[] { 1 });
				os.write(secret.toBytes());
			}
			// len, (is root 0) , len Dis, Dis, len Ris, Ris, tree len , tree
			else {
				recordLen++;
				recordLen += 4;
				for (int i = 0; i < Dis.length; i++) {
					recordLen += Dis[i].getLengthInBytes();
				}
				recordLen += 4;
				for (int i = 0; i < Ris.length; i++) {
					recordLen += Ris[i].getLengthInBytes();
				}

				recordLen += 4;
				byte[] treeBytes = accessTree.toString().getBytes("UTF-8");
				recordLen += treeBytes.length;

				ABE.writeInteger(recordLen, os);
				os.write(new byte[] { 0 });
				ABE.writeInteger(Dis.length, os);
				for (int i = 0; i < Dis.length; i++) {
					os.write(Dis[i].toBytes());
				}
				ABE.writeInteger(Ris.length, os);
				for (int i = 0; i < Ris.length; i++) {
					os.write(Ris[i].toBytes());
				}
				ABE.writeInteger(treeBytes.length, os);
				os.write(treeBytes);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		// System.out.println(Utility.gt("10","b").toString());
		// System.out.println(Utility.lt("10","b").toString());
		// BigInteger y1 = new
		// BigInteger("5243908847495165305277382908302479893829445235410443979422877457286515717375779298009158571463797622138995453477912144123612939339529679027685019250322885");
		// BigInteger y2 = new
		// BigInteger("5243908847495165305277382908302479893829445235410443979422877457286515717375779298009158571463797622138995453477912144123612939339529681904023229330778695");

		// System.out.println(y1.add(y1.subtract(y2)));
		ABE abe = new ABE();

		// System.out.println("abe" + abe);

		// OutputStream os = new ByteArrayOutputStream();
		try {
			// PipedOutputStream out = new PipedOutputStream();
			// PipedInputStream in = new PipedInputStream(out);

			// abe.write(out);

			// ABE abe2 = new ABE(in);
			// System.out.println("abe2:" + abe2);

			Entity root = abe.getRootEntity();

			System.out.println("" + root);
			// root.write(out);
			// ByteArrayInputStream in = new
			// ByteArrayInputStream(out.toByteArray());
			// Entity root2 = new Entity(in);
			// System.out.println("root2"+ root);

			byte[] c = "Mihail".getBytes();
			String s = root.sign("Mihail");
			System.out.println("Valid = " + abe.validateSignature(new String[] { "#level1N=14", "l1=a" }, "Mihail", s));

			// Entity manager = root.derive("(1 a)");
			// Ciphertext ct = abe.encrypt(c, new String[]{"#manager=2"});
			// System.out.println("" + ct);
			// byte[] d = root.decrypt(ct);

			byte[] ciphertext = abe.encrypt(c, new String[] { "a", "b", "c", "level1=A", "level2=B", "level3=C",
					"level4=D", "#level1N=10", "#level2N=3", "#level3N=1", "#level4N=5" });
			byte[] data = root.decrypt(ciphertext);
			
			// System.out.println("ciphertext\n" + ciphertext);
			// ByteArrayOutputStream out = new ByteArrayOutputStream();
			// ciphertext.write(out);
			// ByteArrayInputStream in = new
			// ByteArrayInputStream(out.toByteArray());
			// Ciphertext ciphertext2 = new Ciphertext(abe,in);
			// System.out.println("ciphertext\n" + ciphertext2);

			// System.out.println("" + ciphertext);

			// Entity manager_ceo = root.derive("(4 a b c d )");
			// //manager.derive("(2 b c)");

			// Entity manager = root.derive("(and level1=A (< level1N 13) )");
			// //manager.derive("(2 b c)");
			// Entity manager_ceo = root.derive("(and (< level3 5) a)");
			// //manager.derive("(2 b c)");
			Entity manager = root.derive("(and (< level1N 13) b)"); // manager.derive("(2
																	// b c)");
			// byte[] b = manager.sign(c);
			// System.out.println("Valid = " + abe.validateSignature(new
			// String[]{"#level1N=12"}, c, b));
			String signature = manager.sign("Saman");
			System.out.println("Valid = " + abe.validateSignature(new String[] { "#level1N=14" }, "Saman", signature));

			// System.out.println("manager: " + manager);
			// manager.write(out);
			// ByteArrayInputStream in = new
			// ByteArrayInputStream(out.toByteArray());
			// Entity manager2 = new Entity(in);
			// System.out.println("manager2: " + manager);

			// Entity manager_ceo = root.derive("(and (2 T (1 (2 T T) T)) a)");
			// Entity manager_ceo = root.derive("(and (2 T (1 (2 T F) T)) a)");
			// Entity manager_ceo = root.derive("(and (1 (2 T T) T) a)");
			// Entity manager_ceo = root.derive("(and (1 T T) a)");

			// Entity manager_ceo = root.derive("(1 (< level4 7) )");
			// //manager.derive("(2 b c)");

			// Entity manager_ceo = root.derive("(20 a b c d e f g a b c h i a b
			// c d e f g a b c h i a b c d e f g a b c h i a b c d e f g a b c h
			// i) ");
			// Entity manager_ceo = root.derive("(3 ( 1 ( 1 (1
			// (1(1(1(1(1(1(1(1(1(1(1 a b) b) b)b)b)b)b)b)b)b)b)b)b)b) ( 1 ( 1
			// (1 (1(1(1(1(1(1(1(1(1(1(1 a b) b) b)b)b)b)b)b)b)b)b)b)b)b) ( 1 (
			// 1 (1 (1(1(1(1(1(1(1(1(1(1(1 a b) b) b)b)b)b)b)b)b)b)b)b)b)b) )");

			// System.out.println("CEO Entity: "+manager_ceo);
			// Entity manager_ceo = manager.derive("(< level2N 10)");
			// System.out.println("" + manager_ceo);
			// manager_ceo.decrypt(ciphertext);

		} catch (ExpresionException we) {
			System.out.println("Exception: " + we);
		} catch (Exception e) {
			System.out.println("e:" + e);

		}
	}
}
