package ro.manoli.crypto.abe.kp;

import java.util.ArrayList;

import de.tudresden.inf.lat.jsexp.Sexp;
import de.tudresden.inf.lat.jsexp.SexpFactory;

/**
 * 
 * @author Mihail
 *
 */
public class Utility {
	static boolean isIntNumber(String num) {
		try {
			Integer.parseInt(num);
		} catch (NumberFormatException nfe) {
			return false;
		}
		return true;
	}

	private final static int intSize = 10;

	static Sexp gt(String a, String b) { // a>b
		Sexp result = null;
		boolean a_isNumber = Utility.isIntNumber(a);
		boolean b_isNumber = Utility.isIntNumber(b);
		if ((a_isNumber && b_isNumber) || (!a_isNumber && !b_isNumber))
			return null;

		try {
			int a_i = Integer.parseInt(a);
			result = gt(a_i, b, intSize - 1);
		} catch (NumberFormatException nfe) {
			int b_i = Integer.parseInt(b);
			result = lt(b_i, a, intSize - 1);
		}
		return result;
	}

	static Sexp lt(String a, String b) { // a>b
		Sexp result = null;
		boolean a_isNumber = Utility.isIntNumber(a);
		boolean b_isNumber = Utility.isIntNumber(b);
		if ((a_isNumber && b_isNumber) || (!a_isNumber && !b_isNumber))
			return null;

		try {
			int a_i = Integer.parseInt(a);
			result = lt(a_i, b, intSize - 1);
		} catch (NumberFormatException nfe) {
			int b_i = Integer.parseInt(b);
			result = gt(b_i, a, intSize - 1);
		}
		return result;
	}

	static Sexp lt(int a, String b, int bit) {
		Sexp result = null;
		if (bit == 0) {
			result = lt_bit(a, b, 0);
		} else {
			Sexp eq_bit_expr = null;
			if (getBit(a, bit) == 1)
				eq_bit_expr = eq_bit(a, b, bit);
			Sexp l_expr = lt(a, b, bit - 1);

			// gt_bit or (eq_bit and l)
			Sexp eq_and_l_expr = null;
			if (l_expr != null) {
				if (eq_bit_expr != null) {
					eq_and_l_expr = SexpFactory.newNonAtomicSexp();
					eq_and_l_expr.add(SexpFactory.newAtomicSexp("2"));
					eq_and_l_expr.add(eq_bit_expr);
					eq_and_l_expr.add(l_expr);
				} else {
					eq_and_l_expr = l_expr;
				}

			}

			Sexp lt_bit_expr = lt_bit(a, b, bit);

			if (eq_and_l_expr != null && lt_bit_expr != null) {
				result = SexpFactory.newNonAtomicSexp();
				result.add(SexpFactory.newAtomicSexp("1"));
				result.add(eq_and_l_expr);
				result.add(lt_bit_expr);
			} else if (eq_and_l_expr != null) {
				result = eq_and_l_expr;
			} else if (lt_bit_expr != null) {
				result = lt_bit_expr;
			}
		}
		return result;
	}

	static Sexp lt_bit(int a, String b, int bit) {
		Sexp result = null;
		// a_i=0 and b_i=1
		int a_i = getBit(a, bit);
		if (a_i == 0) {
			result = SexpFactory.newAtomicSexp(b + "@" + bit + "=1");
		}
		return result;
	}

	//
	static Sexp gt(int a, String b, int bit) {
		Sexp result = null;
		if (bit == 0) {
			result = gt_bit(a, b, 0);
		} else {
			Sexp eq_bit_expr = null;
			if (getBit(a, bit) == 0)
				eq_bit_expr = eq_bit(a, b, bit);
			Sexp l_expr = gt(a, b, bit - 1);

			// gt_bit or (eq_bit and l)
			Sexp eq_and_l_expr = null;
			if (l_expr != null) {
				if (eq_bit_expr != null) {
					eq_and_l_expr = SexpFactory.newNonAtomicSexp();
					eq_and_l_expr.add(SexpFactory.newAtomicSexp("2"));
					eq_and_l_expr.add(eq_bit_expr);
					eq_and_l_expr.add(l_expr);
				} else {
					eq_and_l_expr = l_expr;
				}

			}

			Sexp gt_bit_expr = gt_bit(a, b, bit);

			if (eq_and_l_expr != null && gt_bit_expr != null) {
				result = SexpFactory.newNonAtomicSexp();
				result.add(SexpFactory.newAtomicSexp("1"));
				result.add(eq_and_l_expr);
				result.add(gt_bit_expr);
			} else if (eq_and_l_expr != null) {
				result = eq_and_l_expr;
			} else if (gt_bit_expr != null) {
				result = gt_bit_expr;
			}
		}
		return result;
	}

	static Sexp gt_bit(int a, String b, int bit) {
		Sexp result = null;
		// a_i=1 and b_i=0
		int a_i = getBit(a, bit);
		if (a_i == 1) {
			result = SexpFactory.newAtomicSexp(b + "@" + bit + "=0");
		}
		return result;
	}

	static Sexp eq_bit(int a, String b, int bit) {
		// a_i=1 and b_i=0

		Sexp result = SexpFactory.newAtomicSexp(b + "@" + bit + "=" + getBit(a, bit));

		return result;
	}

	static int getBit(int a, int bit) {
		int filter = 0;
		switch (bit) {
		case 0:
			filter = 1;
			break;
		case 1:
			filter = 2;
			break;
		case 2:
			filter = 4;
			break;
		case 3:
			filter = 8;
			break;
		case 4:
			filter = 16;
			break;
		case 5:
			filter = 32;
			break;
		case 6:
			filter = 64;
			break;
		case 7:
			filter = 128;
			break;
		case 8:
			filter = 256;
			break;
		case 9:
			filter = 512;
			break;
		case 10:
			filter = 1024;
			break;
		case 11:
			filter = 2048;
			break;
		case 12:
			filter = 4096;
			break;
		case 13:
			filter = 8192;
			break;
		case 14:
			filter = 16384;
			break;
		case 15:
			filter = 32768;
			break;
		}
		return ((a & filter) == 0) ? 0 : 1;
	}

	static void addBitwiseAtts(String variable, int value, ArrayList<String> attArray) {
		for (int i = 0; i < intSize; i++) {
			attArray.add(variable + "@" + i + "=" + getBit(value, i));
		}
	}

}
