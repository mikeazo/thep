This project aims to provide homomorphic encryption libraries to developers so they can in turn create privacy and confidentiality aware software. See <a href='http://en.wikipedia.org/wiki/Homomorphic_encryption'>Homomorphic_encryption</a> for more information on the general capabilities of this form of encryption.

Currently the code implements the <a href='http://en.wikipedia.org/wiki/Paillier_cryptosystem'>Paillier</a> cryptosystem in Java, along with it's homomorphic operations and key generation. Saving/transporting keys and encrypted integers can be accomplished using methods inherited from _Serializable_.

We have also implemented the GT-SCOT protocol from <a href='http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.59.9123&rep=rep1&type=pdf'><i>Strong Conditional Oblivious Transfer and Computing on Intervals</i></a>.

In the future we hope to implement more cryptosystems and port the library to other languages. For questions, comments, suggestions, or anything else, contact me (mikec AT cs DOT utah DOT edu). I would also be interested in collaboration on any projects you might like to use _thep_ for, so contact me directly for that too.