package thep.paillier;


import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import thep.paillier.exceptions.PublicKeysNotEqualException;

public class EncryptedInteger implements Serializable {
	/**
	 * The serial version ID
	 */
	private static final long serialVersionUID = 1L;
	private BigInteger cipherval;
	private PublicKey	pub;
	private Random rng;
	
	/**
	 * Constructs an encrypted integer version of the given plaintext value
	 * with the given public key.
	 * 
	 * @param plainval the plaintext for the encrypted integer
	 * @param pub the public key which will be used to do the encrypting
	 */
	public EncryptedInteger(BigInteger plainval, PublicKey pub) {
		this.rng = new SecureRandom();
		this.pub = pub;
		this.set(plainval);
	}
	
	/**
	 * Constructs a copy of the other encrypted integer
	 * 
	 * @param other the other encrypted integer
	 */
	public EncryptedInteger(EncryptedInteger other) {
		this.cipherval = other.getCipherVal();
		this.pub = other.getPublicKey();
	}
	
	/**
	 * Sets the encrypted integer to an encrypted version of the plaintext
	 * value
	 * 
	 * @param plainval the new plaintext value that will be encrypted
	 */
	public void set(BigInteger plainval) {
		// Encrypt plainval and store it in cipherval
		BigInteger r;
		BigInteger x;
		
		// Generate random blinding factor less than n
		do {
			r = new BigInteger(this.pub.getBits(), rng);
		} while(r.compareTo(this.pub.getN()) >= 0);
		
		cipherval = this.pub.getG().modPow(plainval, this.pub.getNSquared());
		x = r.modPow(this.pub.getN(), this.pub.getNSquared());
		
		cipherval = cipherval.multiply(x);
		cipherval = cipherval.mod(this.pub.getNSquared());
	}
	
	/**
	 * Adds one encrypted integer to this encrypted integer
	 * 
	 * @param other the encrypted integer to add
	 * @return a new encrypted integer with the encrypted integer added to the current
	 * @throws PublicKeysNotEqualException
	 */
	public EncryptedInteger add(EncryptedInteger other) throws PublicKeysNotEqualException {
		if(!this.pub.equals(other.getPublicKey())) {
			throw new PublicKeysNotEqualException();
		}
		EncryptedInteger tmp_int = new EncryptedInteger(this);
		BigInteger tmp = cipherval.multiply(other.getCipherVal());
		tmp = tmp.mod(pub.getNSquared());
		
		tmp_int.setCipherVal(tmp);
		
		return tmp_int;
	}
	
	/**
	 * Adds a constant to the encrypted integer
	 * 
	 * @param other the constant to be added
	 * @return a new encrypted integer with the constant added to the current
	 */
	public EncryptedInteger add(BigInteger other) {
		EncryptedInteger tmp_int = new EncryptedInteger(this);
		BigInteger tmp = cipherval.multiply(this.pub.getG().modPow(other, this.pub.getNSquared()));
		tmp = tmp.mod(this.pub.getNSquared());
		
		tmp_int.setCipherVal(tmp);
		
		return tmp_int;
	}
	
	/**
	 * Multiplies the encrypted integer by a constant
	 * 
	 * @param other the constant by which to multiply
	 * @return a new encrypted integer equal to the original times the constant
	 */
	public EncryptedInteger multiply(BigInteger other) {
		EncryptedInteger tmp_int = new EncryptedInteger(this);
		BigInteger tmp = cipherval.modPow(other, pub.getNSquared());
		
		tmp_int.setCipherVal(tmp);
		
		return tmp_int;
	}
	
	/**
	 * Rerandomizes the encrypted integer (without needing the private key)
	 * by using the homomorphic properties to add a randomly encrypted version
	 * of zero.
	 * 
	 * Rerandomization is useful so a server does not know that you are
	 * resubmitting a value they have already operated on. For example, if an
	 * untrusted server is given an encrypted integer and performs some math,
	 * then later is given that same ciphertext which resulted from earlier
	 * calculations, the untrusted server has gained some information (i.e. it
	 * is most likely the same value that was operated on earlier).
	 * Rerandomization prevents this.
	 */
	public void rerandomize() {
		BigInteger r = new BigInteger(this.pub.getBits(), rng);
		r = r.modPow(this.pub.getN(), this.pub.getNSquared());
		cipherval = cipherval.multiply(r);
		cipherval = cipherval.mod(this.pub.getNSquared());
	}
	
	/**
	 * Decrypts the current ciphertext value held by the class
	 * 
	 * @param priv the private key do use for decryption
	 * @return A BigInteger of the decrypted value
	 */
	public BigInteger decrypt(PrivateKey priv) {
		// Decrypt the encrypted value
		BigInteger plainval;
		
		plainval = cipherval.modPow(priv.getLambda(), priv.getPublicKey().getNSquared());
		plainval = plainval.subtract(BigInteger.ONE);
		plainval = plainval.divide(priv.getPublicKey().getN());
		plainval = plainval.multiply(priv.getMu());
		plainval = plainval.mod(priv.getPublicKey().getN());
		
		return plainval;
	}
	
	/**
	 * Returns the ciphertext value
	 * 
	 * @return the ciphertext value
	 */
	public BigInteger getCipherVal() {
		return cipherval;
	}
	
	/**
	 * Returns the public key associated with this encrypted integer
	 * @return the public key
	 */
	public PublicKey getPublicKey() {
		return this.pub;
	}
	
	/*
	 * Sets the cipherval, should only be used in this package
	 */
	private void setCipherVal(BigInteger cipherval) {
		this.cipherval = cipherval;
	}
}
