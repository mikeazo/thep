package test.thep.paillier;

import java.math.BigInteger;

import junit.framework.TestCase;
import thep.paillier.EncryptedInteger;
import thep.paillier.EncryptedPolynomial;
import thep.paillier.PrivateKey;
import thep.paillier.PublicKey;
import thep.paillier.exceptions.PublicKeysNotEqualException;
import thep.paillier.exceptions.SizesNotEqualException;

public class EncryptedPolynomialTest extends TestCase {
	private PrivateKey priv;
	private PublicKey pub;
	private EncryptedPolynomial identity;
	private EncryptedPolynomial square;
	private EncryptedPolynomial square_plus10;
	
	public EncryptedPolynomialTest(String name) {
		super(name);
	}
	
	protected void setUp() {
		priv = new PrivateKey(1024);
		pub = priv.getPublicKey();
		
		// Set up identity polynomial
		BigInteger[] id = {BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO};
		identity = new EncryptedPolynomial(id, pub);
		
		// Set up square polynomial
		BigInteger[] sq = {BigInteger.ZERO, BigInteger.ZERO, BigInteger.ONE};
		square = new EncryptedPolynomial(sq, pub);
		
		// Set up square plus 10 (10+x^2) polynomial
		BigInteger[] sq_p10 = {BigInteger.TEN, BigInteger.ZERO, BigInteger.ONE};
		square_plus10 = new EncryptedPolynomial(sq_p10, pub);
	}
	
	public void testEvaluate() throws PublicKeysNotEqualException {
		EncryptedInteger ans = identity.evaluate(BigInteger.TEN);
		assertEquals(BigInteger.TEN, ans.decrypt(priv));
		
		ans = square.evaluate(BigInteger.TEN);
		assertEquals(BigInteger.TEN.pow(2), ans.decrypt(priv));
		
		BigInteger twelve = new BigInteger("12");
		BigInteger expected = twelve.pow(2).add(BigInteger.TEN);
		ans = square_plus10.evaluate(twelve);
		assertEquals(expected, ans.decrypt(priv));
	}
	
	public void testAdd() throws PublicKeysNotEqualException, SizesNotEqualException {
		// Try sum of identity and square
		EncryptedPolynomial ans = identity.add(square);	// should yield f(x) = x + x^2 [0, 1, 1]
		BigInteger[] expected1 = {BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE};
		
		// Decrypt coefficients and make sure they are what was expected
		for (int i=0; i < expected1.length; i++) {
			assertEquals(expected1[i], ans.getCoefficients()[i].decrypt(priv));
		}
		
		// Try sum of identity and square and square_plus10
		ans = ans.add(square_plus10); // should yield f(x) = 10 + x + 2x^2 [10, 1, 2]
		BigInteger[] expected2 = {BigInteger.TEN, BigInteger.ONE, new BigInteger("2")};
		
		// Decrypt coefficients and make sure they are what was expected
		for (int i=0; i < expected2.length; i++) {
			assertEquals(expected2[i], ans.getCoefficients()[i].decrypt(priv));
		}
	}
}
