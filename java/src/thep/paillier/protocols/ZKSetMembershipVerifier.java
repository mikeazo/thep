package thep.paillier.protocols;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

import thep.paillier.EncryptedInteger;
import thep.paillier.PublicKey;
import thep.paillier.exceptions.ZKSetMembershipException;

public class ZKSetMembershipVerifier {
	// class members
	private BigInteger[] uVals;
	private BigInteger e;
	private PublicKey pub;
	private EncryptedInteger c;
	private BigInteger[] theSet;
	private MessageDigest hashFunc;
	
	/**
	 * Constructor
	 * 
	 * @param pub the public key
	 * @param c the cipher text
	 * @param uVals the u values from the prover
	 * @param theSet the set on which to test membership
	 * @throws ZKSetMembershipException 
	 */
	public ZKSetMembershipVerifier(PublicKey pub, EncryptedInteger c, BigInteger[] uVals,
			BigInteger[] theSet) throws ZKSetMembershipException {
		this.pub = pub;
		this.c = c;
		this.uVals = uVals;
		this.theSet = theSet;
		
		try {
			this.hashFunc = java.security.MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			throw new ZKSetMembershipException("Could not initialize the hash function for non-interactive mode");
		}
	}
	
	/**
	 * Generates the challenge for the prover
	 * 
	 * @param A the upper bound on the challenge. The probability that
	 * a malicious prover can complete the protocol is 1/A. Multiple
	 * rounds of the protocol can be run for stronger assurances. This
	 * step in the protocol can be replaced using the Fiat-Shamir paradigm
	 * to make the zero knowledge proof non-interactive.
	 * @return the challenge
	 */
	public BigInteger genChallenge(BigInteger A) {
		Random rng = new SecureRandom();
		
		// generate a random challenge
		this.e = new BigInteger(A.bitLength(), rng);
		// Make sure the random challenge is less than A
		while (this.e.compareTo(A) > 0) {
			this.e = new BigInteger(A.bitLength(), rng);
		}
		
		return this.e;
	}
	
	/**
	 * Checks the response from the prover
	 * 
	 * @param eVals the e values given by the prover
	 * @param vVals the v values given by the prover
	 * @return true if the response check is OK, otherwise false
	 * @throws ZKSetMembershipException
	 */
	public boolean checkResponse(BigInteger[] eVals, BigInteger[] vVals) throws ZKSetMembershipException {
		if (eVals.length != vVals.length) {
			throw new ZKSetMembershipException("Arrays passed to checkResponse must be same length");
		}
		
		BigInteger eValAccum = BigInteger.ZERO;
		BigInteger N_Squared = this.pub.getNSquared();
		
		for (BigInteger tmp : eVals) {
			eValAccum = eValAccum.add(tmp).mod(this.pub.getN());
		}
		
		if (eValAccum.compareTo(this.e) != 0) {
			return false;
		}
		
		for (int i=0; i<eVals.length; i++) {
			BigInteger lhs = vVals[i].modPow(this.pub.getN(), N_Squared);
			BigInteger rhs = this.pub.getG().modPow(this.theSet[i], N_Squared);
			rhs = rhs.modInverse(N_Squared);
			rhs = rhs.multiply(this.c.getCipherVal()).mod(N_Squared);
			rhs = rhs.modPow(eVals[i], N_Squared);
			rhs = rhs.multiply(this.uVals[i]).mod(N_Squared);
			
			if (lhs.compareTo(rhs) != 0) {
				return false;
			}
		}
		
		return true;
	}
	
	/**
	 * Checks the response from the prover. Uses the Fiat-Shamir heuristic
	 * 
	 * @param eVals the e values given by the prover
	 * @param vVals the v values given by the prover
	 * @param digest the challenge value used by the prover
	 * @return true if the response check is OK, otherwise false
	 * @throws ZKSetMembershipException
	 */
	public boolean checkResponseNonInteractive(BigInteger[] eVals, BigInteger[] vVals, 
			BigInteger digest) throws ZKSetMembershipException {
		// make sure lengths are equal
		if (eVals.length != vVals.length) {
			throw new ZKSetMembershipException("Arrays passed to checkResponse must be same length");
		}
		
		// check the given digest
		for (int i=0; i<this.uVals.length; i++) {
			this.hashFunc.update(this.uVals[i].toByteArray());
		}
		
		BigInteger testDigest = new BigInteger(this.hashFunc.digest()).mod(new BigInteger("128"));
		
		if (!testDigest.equals(digest))	{
			return false;
		}
		
		this.e = digest;
		
		
		return this.checkResponse(eVals, vVals);
	}
}
