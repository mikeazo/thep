package test.thep.paillier;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.Random;

import junit.framework.TestCase;
import thep.paillier.EncryptedInteger;
import thep.paillier.PrivateKey;
import thep.paillier.PublicKey;
import thep.paillier.exceptions.PublicKeysNotEqualException;

public class EncryptedIntegerTest extends TestCase {
	private PrivateKey priv;
	private PublicKey pub;
	private Random rng;
	
	public EncryptedIntegerTest(String name) {
		super(name);
	}
	
	protected void setUp() {
		priv = new PrivateKey(1024);
		pub = priv.getPublicKey();
		rng = new Random();
	}
	
	/*
	 * Create an encrypted integer, then decrypt to make sure it decrypts
	 * properly.
	 */
	public void testCreation() {
		BigInteger tmp = new BigInteger(1024, rng);
		tmp = tmp.mod(pub.getN());
		EncryptedInteger e_int = new EncryptedInteger(tmp, pub);
		assertNotNull(e_int);
		assertEquals(tmp, e_int.decrypt(priv));
	}
	
	/*
	 * Tests the addition of a constant to an EncryptedInteger
	 */
	public void testAdditionOfConstant() {
		BigInteger tmp1 = new BigInteger(1024, rng);
		BigInteger tmp2 = new BigInteger(1024, rng);
		BigInteger expected = tmp1.add(tmp2);
		expected = expected.mod(pub.getN());
		EncryptedInteger e_int = new EncryptedInteger(tmp1, pub);
		e_int = e_int.add(tmp2);
		assertEquals(expected, e_int.decrypt(priv));
	}
	
	/*
	 * Tests the multiplication of a constant to an EncryptedInteger
	 */
	public void testMultiplicationOfConstant() {
		BigInteger tmp1 = new BigInteger(1024, rng);
		BigInteger tmp2 = new BigInteger(1024, rng);
		BigInteger expected = tmp1.multiply(tmp2);
		expected = expected.mod(pub.getN());
		EncryptedInteger e_int = new EncryptedInteger(tmp1, pub);
		e_int = e_int.multiply(tmp2);
		assertEquals(expected, e_int.decrypt(priv));
	}
	
	/*
	 * Tests the multiplication of a constant to an EncryptedInteger
	 */
	public void testAdditionOfEncryptedInteger() {
		BigInteger tmp1 = new BigInteger(1024, rng);
		BigInteger tmp2 = new BigInteger(1024, rng);
		BigInteger expected = tmp1.add(tmp2);
		expected = expected.mod(pub.getN());
		EncryptedInteger e_int1 = new EncryptedInteger(tmp1, pub);
		EncryptedInteger e_int2 = new EncryptedInteger(tmp2, pub);
		try {
			e_int1 = e_int1.add(e_int2);
		} catch (PublicKeysNotEqualException e) {
			fail();
		}
		assertEquals(expected, e_int1.decrypt(priv));
	}
	
	/*
	 * Tests the multiplication of a constant to an EncryptedInteger
	 */
	public void testBadAdditionOfEncryptedInteger() {
		PrivateKey tmp_priv = new PrivateKey(1024);
		BigInteger tmp1 = new BigInteger(1024, rng);
		BigInteger tmp2 = new BigInteger(1024, rng);
		BigInteger expected = tmp1.add(tmp2);
		expected = expected.mod(pub.getN());
		EncryptedInteger e_int1 = new EncryptedInteger(tmp1, pub);
		EncryptedInteger e_int2 = new EncryptedInteger(tmp2, tmp_priv.getPublicKey());
		try {
			e_int1 = e_int1.add(e_int2);
			fail();
		} catch (PublicKeysNotEqualException e) {
		}
	}
	
	/*
	 * Test the rerandomize function.
	 */
	public void testRerandomize() {
		BigInteger tmp = new BigInteger(1024, rng);
		tmp = tmp.mod(pub.getN());
		EncryptedInteger e_int = new EncryptedInteger(tmp, pub);
		BigInteger c1 = e_int.getCipherVal();
		BigInteger p1 = e_int.decrypt(priv);
		e_int.rerandomize();
		BigInteger c2 = e_int.getCipherVal();
		BigInteger p2 = e_int.decrypt(priv);
		
		assertNotSame(c1, c2);
		assertEquals(p1, p2);
	}
	
	/*
	 * Tests serialization of encrypted integers
	 */
	public void testSerializable() throws IOException, ClassNotFoundException {
		BigInteger tmp = new BigInteger(1024, rng);
		tmp = tmp.mod(pub.getN());
		EncryptedInteger e_int1 = new EncryptedInteger(tmp, pub);
		
		// Save the integer to an output stream
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(baos);
		oos.writeObject(e_int1);
		
		// Load a new object from the output stream
		ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
		ObjectInputStream ois = new ObjectInputStream(bais);
		EncryptedInteger e_int2 = (EncryptedInteger)ois.readObject();
		
		// Check that everything went alright
		assertEquals(tmp, e_int2.decrypt(priv));
	}
	
	/*
	 * Tests copy constructor
	 */
	public void testCopy() {
		BigInteger tmp = new BigInteger(1024, rng);
		tmp = tmp.mod(pub.getN());
		EncryptedInteger e_int = new EncryptedInteger(tmp, pub);
		EncryptedInteger copy = new EncryptedInteger(e_int);
		assertEquals(e_int.decrypt(priv), copy.decrypt(priv));
	}
	
}
