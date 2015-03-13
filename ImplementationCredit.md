# Introduction #

We used a number of different academic papers, articles, etc, while implementing this project. We list these here to give credit.


# Details #

For the most part, we used Wikipedia's [Paillier\_cryptosystem](http://en.wikipedia.org/wiki/Paillier_cryptosystem) and a Masters Thesis by Kevin Henry of the University of Waterloo titled [The Theory and Applications of Homomorphic Cryptography](http://uwspace.uwaterloo.ca/bitstream/10012/3901/1/uw-ethesis.pdf) in implementing the Paillier package and the EncryptedInteger class.

The rerandomize function in the Paillier EncryptedInteger class came from [Strong Conditional Oblivious Transfer and Computing on Intervals](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.59.9123&rep=rep1&type=pdf) by Ian F. Blake and Vladimir Kolesnikov, both from the University of Toronto.

The GT-SCOT protocol comes from [Strong Conditional Oblivious Transfer and Computing on Intervals](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.59.9123&rep=rep1&type=pdf) by Blake and Kolesnikov of the University of Toronto.

For the EncryptedPolynomial class, we followed the ideas outlined in Kevin Henry's Masters Thesis [The Theory and Applications of Homomorphic Cryptography](http://uwspace.uwaterloo.ca/bitstream/10012/3901/1/uw-ethesis.pdf).

The zero-knowledge proof of set membership comes from [Practical Multi-candidate Election System](http://people.csail.mit.edu/rivest/voting/papers/BaudronFouquePointchevalPoupardStern-PracticalMultiCandidateElectionSystem.pdf).