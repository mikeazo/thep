package thep.paillier.protocols;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import thep.paillier.EncryptedInteger;
import thep.paillier.PublicKey;
import thep.paillier.exceptions.ZKSetMembershipException;

public class ZKSetMembershipProver {
	// class members
	private BigInteger[] eVals;
	private BigInteger[] vVals;
	private PublicKey pub;
	private BigInteger[] theSet;
	private int msgIndex;
	private EncryptedInteger ciphertext;
	private BigInteger rho;
	Random rng;
	
	/**
	 * The default constructor
	 * @param pub the public key
	 * @param theSet the set we want to prove cipherText is in
	 * @param msgIndex the index we are claiming cipherText is in theSet
	 * @param cipherText the cipher text for the proof
	 */
	public ZKSetMembershipProver(PublicKey pub, BigInteger[] theSet, 
			int msgIndex, EncryptedInteger cipherText) {
		this.pub = pub;
		this.theSet = theSet;
		this.msgIndex = msgIndex;
		this.ciphertext = cipherText;
		
		this.rng = new SecureRandom();
		
		this.rho = null;
	}
	
	/**
	 * Generates the commitments for proving that the cipher text is in the given set.
	 * The commitments are returned and should be sent to the verifier.
	 *
	 * @return the commitments
	 * @throws ZKSetMembershipException
	 */
	public BigInteger[] genCommitments() throws ZKSetMembershipException {
		int setLen = theSet.length;
		BigInteger[] commitments = new BigInteger[setLen];
		BigInteger N = this.pub.getN();
		BigInteger N_squared = this.pub.getNSquared();
		BigInteger c = ciphertext.getCipherVal();
		BigInteger c_inverse = c.modInverse(N_squared);
		BigInteger g = this.pub.getG();
		int bits = this.pub.getBits();
		
		if (msgIndex >= setLen || msgIndex < 0) { // check the input data
			throw new ZKSetMembershipException("Index out of Range");
		}
		
		// generate a random rho
		this.rho = new BigInteger(bits, this.rng);
		// rho needs to be less than N, but not zero
		while (rho.compareTo(N) > 0 || rho.compareTo(BigInteger.ZERO) == 0) {
			rho = new BigInteger(bits, this.rng);
		}
		
		this.eVals = new BigInteger[setLen];
		for (int i=0; i<setLen; i++) {
			// generate random e value
			this.eVals[i] = new BigInteger(bits, this.rng);
			// the e value must be less than n
			while (this.eVals[i].compareTo(N) > 0) {
				this.eVals[i] = new BigInteger(bits, this.rng);
			}
		}
		
		this.vVals = new BigInteger[setLen];
		for (int i=0; i<setLen; i++) {
			// generate random v value
			this.vVals[i] = new BigInteger(bits, this.rng);
			// the v value must be less than n and not 0
			while (this.vVals[i].compareTo(N) > 0 || this.vVals[i].compareTo(BigInteger.ZERO) == 0) {
				this.vVals[i] = new BigInteger(bits, this.rng);
			}
		}
		
		// calculate the commitments
		for (int i=0; i<setLen; i++) {
			if (i == msgIndex) {
				commitments[i] = rho.modPow(N, N_squared);
			}
			else {
				BigInteger tmp1 = vVals[i].modPow(N, N_squared);
				BigInteger tmp2 = g.modPow(theSet[i], N_squared);
				tmp2 = tmp2.multiply(c_inverse);
				tmp2 = tmp2.modPow(eVals[i], N_squared);
				commitments[i] = tmp1.multiply(tmp2);
				commitments[i] = commitments[i].mod(N_squared);
			}
		}
		
		return commitments;
	}
	
	/**
	 * Computes the provers response to the challenge e. The prover should
	 * then use getVs() and getEs() and send those values to the verifier.
	 * 
	 * @param e the challenge
	 * @param r the random number used during encryption
	 * @throws ZKSetMembershipException 
	 */
	public void computeResponse(BigInteger e, BigInteger r) throws ZKSetMembershipException {
		if (this.rho == null) {
			throw new ZKSetMembershipException("genCommitments() must be called before computeResponse()");
		}
		
		BigInteger N = this.pub.getN();
		
		// compute e_i
		BigInteger tmp1 = e;
		for (int i=0; i<this.eVals.length; i++) {
			if (i != msgIndex) {
				tmp1 = tmp1.subtract(this.eVals[i]);
			}
		}
		BigInteger e_i = tmp1.mod(N);
		this.eVals[msgIndex] = e_i;
		
		// compute v_i
		BigInteger v_i = this.rho.multiply(r.modPow(e_i, N)).mod(N);
		tmp1 = tmp1.divide(N);
		tmp1 = this.pub.getG().modPow(tmp1, N);
		v_i = v_i.multiply(tmp1).mod(N);
		this.vVals[msgIndex] = v_i;
	}
	
	/**
	 * The V values needed for the last part of the proof
	 * @return the v values
	 */
	public BigInteger[] getVs() {
		return this.vVals;
	}
	
	/**
	 * The E values needed for the last part of the proof
	 * @return the e values
	 */
	public BigInteger[] getEs() {
		return this.eVals;
	}
}
