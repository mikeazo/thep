# Introduction #

thep can handle negative number (adding two encrypted negatives, multiplying by a negative number, etc). This includes cases where the result is also negative. There are a few subtleties though, below I describe them. In the [java/src/test/thep/paillier/EncryptedIntegerTest.java](http://code.google.com/p/thep/source/browse/trunk/java/src/test/thep/paillier/EncryptedIntegerTest.java) source file, there are a few examples that use negative numbers.


# Details #

Working with negative numbers is very straight forward as long as the result of the operation is positive. Just do the operation and then decrypt. For example (_priv_ and _pub_ are the private and public keys):
```
EncryptedInteger eint_1 = new EncryptedInteger(BigInteger("2500"), pub);
EncryptedInteger eint_2 = new EncryptedInteger(BigInteger("1000"), pub);
eint_2 = eint_2.mutiply(new BigInteger("-1"));
EncryptedInteger eint_ans = eint_1.add(eint_2);
System.out.println(eint_ans.decrypt(priv));
```
Will output _1500_ as expected.

As another example, consider the following:
```
EncryptedInteger eint_1 = new EncryptedInteger(BigInteger("-10"), pub);
System.out.println(eint_1.decrypt(priv));
```
The output of this will be a very large (random looking) number not equal to negative ten. The number is actually not random. It is equal to _-10 mod N_. To get the right answer we can do:

```
EncryptedInteger eint_1 = new EncryptedInteger(BigInteger("-10"), pub);
BigInteger ans = eint_1.decrypt(priv);
ans.subtract(pub.getN());
System.out.println(ans);
```

When dealing with applications which might have to decrypt negative numbers, a simple heuristic should suffice.
```
BigInteger ans = eint_1.decrypt(priv);
if (ans.compare(threshold) == 1)
    ans = ans.subtract(pub.getN());
System.out.println(ans);
```
In this case, we have some threshold value (application specific) and if the decrypted integer is greater than that, we assume the result should have been negative. This will work with very high probability as long as a good _threshold_ is chosen. For example, if my _eint\_1_ contains the number of dollars in my bank account, _threshold=1000000_ might be a good value (unfortunately).