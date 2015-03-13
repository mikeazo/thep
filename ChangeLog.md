# Introduction #
Below we have kept a list of changes between releases.

## thep-0.2 (8/18/2011) ##
New Functionality
  * Added a zero-knowledge set membership proof. Both interactive and non-interactive (via Fiat-Shamir) are available. See the test classes in the source for an example.
  * Added the ability to specify the BigInteger class to use for large numbers. Especially handy for using NativeBigInteger to speed things up [jbigi](http://www.i2p2.de/jbigi.html)

## thep-0.1.1 (3/25/2011) ##
Bug fix
  * Fixed bug where SecureRandom rng was not initialized in copy constructor

## thep-0.1 (5/21/2010) ##
Initial release of thep. Includes:
  * Encrypted integers and polynomials
  * Key generation using a secure random number generator
  * The GTSCOT protocol (see [ImplementationCredit](ImplementationCredit.md) for more information)