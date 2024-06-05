# This document is required.

#AES Presentation Slides

## What is AES?
AES or Advanced Encryption Standard is a specification for the encryption of electronic data. AES uses symmetric encryption, meaning it requires the same key to encrypt and decrypt data.

AES is a block cipher, so it encrypts data in blocks, always 128 bits in length. AES uses a specific algorithm comprised of several operations used to obscure the relationship between the plaintext data block and the ciphertext data block. Each operation is repeated for a specific number of rounds, which depends on the key size. 

AES has three different versions available, with the only major difference being the size of the key that is used to execute its algorithms. Each version has the key size specified in its name. There is AES-128, AES-192, and AES-256.  

## What’s the difference between each version of AES?
If the key length for AES gets bigger, there is, of course, more security. Because AES-256 has a larger key, it will be significantly more difficult to break compared to its smaller counterpart, AES-128. 
However, no matter the key size, each version of AES is incredibly secure, and both versions are still considered safe to use for encrypting sensitive information.

Additionally, there is the power it takes to encrypt using each version of AES. AES-128 is typically used because it's much quicker and takes less computational power than AES-256 but still maintains security.  
The main difference that comes from key sizes is that the number of rounds for each operation also differs between each, with 10, 12, and 14 rounds respectively.

## Blocks in AES
Since AES is a block cipher, the first step in encrypting data is dividing the plaintext into data blocks of four bytes by four bytes, for a total of 128 bits. 

For example, if you had a phrase like “AES is a very secure method of encryption”, then the first block would look like this:

A |	2 | i |	e
--- |--- | --- | ---
E	| 5 |	s |	r
S	|	6 |  | y 
- |  	| v	| 

The rest of the plaintext is then continued in the other blocks. When a block has no plaintext left to put in it, it puts in padding bytes, because AES needs complete blocks to be able to function.
