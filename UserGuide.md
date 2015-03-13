# EncryptedInteger #
An EncryptedInteger is just that, an encrypted integer. Lets look at some example code to see how to use it. For this code, assume you already have a public key called _pub_
```
// Create two encrypted integers
a = new EncryptedInteger(BigInteger.ONE, pub);
b = new EncryptedInteger(BigInteger.ONE, pub);

// Use the homomorphic operation "add" on the integers
EncryptedInteger c = a.add(b); // When decrypted, c should have the value 2
```
You'll notice that we said the homomorphic operation "add" when we called _a.add(b)_. The "add" is in quotes since it isn't really adding anything, but actually computes (a\*b mod n^2). This does, however, result in the addition of the plaintexts, but the user of the library need not know how the underlying homomorphic crypto system works. They can continue to think as if they are working on plaintext integers (i.e. calling add results in an addition operation on plaintexts).

This is the same for the _multiply(BigInteger other)_ and _add(BigInteger other)_ functions. The code doesn't actually perform a multiply (or add) on the ciphertext, but the result is as if you had multiplied (or added) the ciphertext with the constant value _other_.

As a developer you just have to think in terms of what operation you want to perform on the plaintext value(s) and call the appropriate function. That frees you from having to understand the underlying crypto system.