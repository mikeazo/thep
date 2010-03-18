package thep.paillier;

import java.io.Serializable;
import java.math.BigInteger;

import thep.paillier.exceptions.PublicKeysNotEqualException;
import thep.paillier.exceptions.SizesNotEqualException;

public class EncryptedPolynomial implements Serializable {

	/**
	 * default serial ID
	 */
	private static final long serialVersionUID = 1L;
	private EncryptedInteger[] coefficients;
	private PublicKey pub;
	
	/**
	 * Constructs a single variable encrypted polynomial object of the form f(x) = (c_0 + c_1*x + c_2*x^2 + ... + c_n*x^n)
	 * 
	 * @param coefficients the coefficients of the polynomial (c_0 + c_1*x + c_2*x^2 + ... + c_n*x^n)
	 * @param pub the public key associated with the polynomial
	 */
	public EncryptedPolynomial(BigInteger[] coefficients, PublicKey pub) {
		this.pub = pub;
		this.coefficients = new EncryptedInteger[coefficients.length];
		
		// Encrypt each coefficient
		for (int i=0; i < this.coefficients.length; i++) {
			this.coefficients[i] = new EncryptedInteger(coefficients[i], this.pub);
		}
	}
	
	/**
	 * Constructs a copy of the given encrypted polynomial
	 * 
	 * @param other the encrypted polynomial to copy
	 */
	public EncryptedPolynomial(EncryptedPolynomial other) {
		this.pub = other.getPublicKey();
		this.coefficients = other.getCoefficients();
	}
	
	/**
	 * Evaluates an encrypted polynomial at the given point
	 * 
	 * @param point the point at which to evaluate the polynomial
	 * @return an encrypted integer form of the polynomial evaluated at the given point
	 * @throws PublicKeysNotEqualException
	 */
	public EncryptedInteger evaluate(BigInteger point) throws PublicKeysNotEqualException {
		EncryptedInteger accumulator = new EncryptedInteger(BigInteger.ZERO, pub);
		
		for (int i=0; i < this.coefficients.length; i++) {
			accumulator = accumulator.add(this.coefficients[i].multiply(point.pow(i)));
		}
		
		return accumulator;
	}
	
	/**
	 * Adds two encrypted polynomials together
	 * 
	 * @param other the other polynomial to add to this
	 * @return a new encrypted polynomial equal to the sum
	 * @throws PublicKeysNotEqualException
	 * @throws SizesNotEqualException
	 */
	public EncryptedPolynomial add(EncryptedPolynomial other) throws PublicKeysNotEqualException, SizesNotEqualException {
		if (!this.pub.equals(other.getPublicKey()))
			throw new PublicKeysNotEqualException("Encrypted polynomials must have same public key to be added");
		
		if (this.coefficients.length != other.getCoefficients().length)
			throw new SizesNotEqualException("Encrypted polynomials must have same order to add");
		
		// Create temporary object which will be returned as the result
		EncryptedPolynomial tmp = new EncryptedPolynomial(this);
		EncryptedInteger[] tmp_coefficients = new EncryptedInteger[this.coefficients.length];
		
		for (int i=0; i < tmp_coefficients.length; i++) {
			tmp_coefficients[i] = this.coefficients[i].add(other.getCoefficients()[i]);
		}
		
		tmp.setCoefficients(tmp_coefficients);
		return tmp;
	}
	
	/*
	 * Getters
	 */
	public PublicKey getPublicKey() {
		return this.pub;
	}
	
	public EncryptedInteger[] getCoefficients() {
		return this.coefficients;
	}
	
	/*
	 * Setters
	 */
	private void setCoefficients(EncryptedInteger[] coefficients) {
		this.coefficients = coefficients;
	}
}
