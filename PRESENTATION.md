# This document is required.

# AES Presentation Slides

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

For example, if you wanted to encrypt a phrase like 'AES is a very secure method of encryption', then the first block would look like this:

A |	i | v |	s
--- |--- | --- | ---
E	| s |	e |	e
S	|	\	 | r | c
\ 	| a	| y	| u

The rest of the plaintext is then continued in the other blocks. When a block has no plaintext left to put in it, it puts in padding bytes, because AES needs complete blocks to be able to function.

### Initialization
In AES, these plaintext blocks are initialized when they are copied into data structures known as `state arrays`. A state array simply refers to the data structure that is used to hold the results after each encryption/decryption process, and is the same as representing the 4x4 matrix of bytes. 
It is the state array that undergoes each transformation after every round. 

## Constants used in AES

### Initialization Vector
In AES, an initialization vector is often generated to randomize encryption and is only used once. 
The IV is meant to be a unique and unpredictable value and does not need to be hidden like the key does.

### Rcon
Rcon, or Round Constants, is a series of predetermined values that are used to generate new round keys from the original key during Key Expansion. 
Rcon is used to introduce greater variety for key generation, and it makes sure each round key is unique. Rcon helps to prevent key-related attacks.

### Sbox
SBox, or substitution box, is a tool used during substitution operations to replace one byte for another. It is essentially a table or 16 x 16 Matrix that serves as a look-up box, where every byte value from 0x00 to 0xFF leads to a different byte output.
It is meant to further introduce confusion into the encryption process to stop and disrupt any patterns that may form. 

## What are keys and rounds in AES?
Depending on the key size, each variant of AES has a different number of rounds. A round is simply the series of transformations a block goes through to make an encrypted ciphertext block.

The `keys` used in AES are made of 32-bit (or 4 byte) 'words'. 
The cipher key in AES-256, for example, would be 8 'words' long. 
Example: keyfor256needtobe32characterslon
Split into words would look like this:
keyf 	or25 	6nee 	dtob 	e32c 	hara 	cter 	slon

In the process of encryption, the key is split into several other smaller keys using a key expansion routine. These smaller keys, known as round keys, are each used for separate rounds of encryption, which are determined by a generated key schedule.

## How does key expansion work?
Key expansion is a routine performed within AES to generate the key schedule. 
Here's how it works:
The key expansion generates a total amount of X `words`, where X is the initial set of words from the key, multiplied by the number of rounds plus one. 

Here is the typical equation used to express this equation, where `Nb` is the initial set of words (also referred to as the number of columns comprising the state) and `Nr` is the number of rounds.

`X = Nb (Nr + 1)`

In the case of AES-256,  there are 14 rounds and 4 initial words so:

`X  =  4 x (14+1) = 60 words` 

The key schedule then, for AES-256, is `60 words`, or 240 bytes.

The expansion algorithm first starts by copying the original encryption key into the first round key, and then generates additional round keys through other operations to provide variety.
The operations include rotWord, which rotates the word a byte to the left, and subWord, which substitutes a byte using the SBox. 

To generate a new key, the previous round key is taken and XORed against Rcon, before being rotated, and then substituted.

## AES Modes

### ECB
Electronic Code Book (ECB) is the simplest block cipher mode of AES because it encrypts every block of plaintext data separately. Because the other blocks do not rely on previous ciphertext blocks for encryption, it is the least secure of all the modes. When AES uses ECB mode, identical plaintext blocks will result in identical ciphertext blocks, which can hinder security, as it is easier to identify identical blocks and guess the original. 

Although ECB is faster and easier to implement, it is much more limited in terms of encryption and security.

### CBC
Cipher block chaining is the most commonly used mode when using AES. Unlike EBC, CBC uses previous ciphertext blocks for the encryption of the next block. Each plaintext block is XORed against the ciphertext of the previous block encrypted, meaning each block affects every other block after it. 
It also requires the use of an IV to encrypt the first block, which also ensures randomness and greater security. There is greater security in CBC mode, but it is slower to process because of the way the blocks are dependent on each other for encryption.  

### CFB
CFB is Cipher Feedback Mode and is similar to CBC in that it also requires an IV and has ciphertext blocks dependent on previous blocks. In CFB, previous ciphertext blocks are encrypted and XORed with the plaintext to make the ciphertext. 

### OFB
Output feedback mode uses the encryption of the previous ciphertext to generate a keystream. This keystream is then XORed against the plaintext to produce the ciphertext, similar to CFB. 

### CTR
Counter mode takes a counter value that is encrypted and XORs it with the plaintext to produce the ciphertext. Like ECB, CTR mode does not rely on previous blocks for encryption and can encrypt blocks independently through parallel encryption. Since the counter values are different between blocks, there is no direct relationship between different plaintext and ciphertext blocks.

However, using a counter may make it more difficult to retrieve the plaintext as both sides, those receiving and sending the message, must keep track of the counter separately. 

## Operations in AES
AES consists of several rounds that use four main functions to encrypt blocks of plaintext. The following operations are done in every round except for MixColumns, which is omitted from the final round.
  * SubBytes
  * ShiftRows
  * MixColumns
  * AddRoundKey

### SubBytes
The SubBytes operation uses substitution to change each byte of the block with another block according to the specific fixed table, the Sbox. Each byte is substituted independently from the others within each block. 
This substitution method is meant to make it harder to find patterns in encrypted data.

### ShiftRows
In this transformation, bytes in each row of the block are repeatedly shifted to the left. The first row remains the same, while the second row shifts over one, the third shifts over two, and the last row shifts over three. (insert image here)

### MixColumns
MixColumns uses Matrix multiplication and multiplies a constant matrix with each column in the state array to get a new one for the resultant state array. This step is omitted in the last round, for several reasons. The purpose of mixColumns is to increase the complexity of the transformation, therefore spreading greater encryption across the entire block. However, this is not needed by the last round as the encryption process is nearing its end. Leaving out mixColumns for the last round does not affect security and only makes the end of the process more efficient. 

### Add Round Key
The block data in the state array is XORed against the given key generated and passes on that state array as input to the next step.

## How secure exactly is AES?
 AES is considered one of the most secure encryption algorithms used today, for several reasons. For one, the many operations used in AES enhance security by making the relationship between the ciphertext and plaintext as complex as possible, with the plaintext data affecting almost every part of the ciphertext. Especially in CBC mode, AES makes sure that small changes in the plaintext are reflected in large changes in the ciphertext, making it increasingly difficult to find patterns or predict the output. 

For example, if we use the plaintext `hello there` with the key `12345678901234561234567890123456` and encrypt it using AES-256 with mode CBC, the output would be:

`y2YR2mlpziZEdGPC9HLlBQ==`

But if we change the plaintext just a small amount into "hello therf", and keep everything the same, the output is virtually completely different:

`xBlePzEiFUMA1JJ7VH1e2Q==`

### Analyzing AES
Cracking AES has never been done before because of how difficult it is given the type of encryption AES implements. For one, it is practically impossible to brute force, as even with a smaller key like in AES-128, there would be thousands of possible combinations for keys. Brute-forcing would require testing every key by decrypting each block through every round and operation. It would take up too many resources computationally, and trying to implement it would be generally impractical. Because of this, the only real weakness AES has is key-related attacks, which do not affect the security of the algorithm itself. 

However, there have been several attempts at attacks on AES, mostly through analyzing the AES algorithm and trying to exploit weaknesses through the key. So far though, the only attacks that have been published are entirely theoretical. Though they are computationally faster than a brute force attack, they are still not feasible and largely impractical.

## Other Related Topics
### How are keys securely distributed? 
The distribution of the key is perhaps the most important aspect of being able to encrypt and decrypt AES. Because the key must remain secret and is only shared between the sending and receiving parties, many use the DH key exchange.
The DH, or Diffie-Helman Key exchange is a secure method of exchanging keys by using both a private key and a public key.

First, the two parties agree on public parameters which they alter with their secret key. Both parties then send their resulting key, which is public, to the other party. The two parties then combine their secret key again with the key they were given to make a new secret key. This way, both keys are the same, but neither of the two parties know about the other’s secret key, so no one can generate their final key.

### Significant Events in AES history
The National Institute of Standards and Technology, NIST, proposed selecting a new encryption standard to replace DES in 1997. Fifteen algorithms were submitted from around the world, one of which being the Rijndael Block Cipher. After extensive evaluation, Rijndael, designed by Belgian cryptographers Vincent Rijment and Joan Daemen, was selected as the Advanced Encryption Standard.

### How has AES held up against cyberattacks?
Given that it's still the national standard, it's evident that it is still a strong cipher. Until recently, the most notable type of attack on the algorithm was a Biclique attack, which reduced the 2^256 complexity to 2^254.4. While that means it cut down the complexity by more than half and was significant faster than a brute force, the attack has no practical implications and didn't pose any significant threat. Recently, however, attack methods continue to advance. The Multiset Attack, which analyzes the ciphertext bytes and sees if they are "balanced", uses results from the analysis to find "distinguishers" that help predict how many rounds of AES it may have gone through, reducing the time complexity to 2^103 under optimal conditions. Low-Data Complexity Attacks target the issue of the absurdly high amount of data traditionally used when attacking AES, which has niche uses despite AES's diffusion and brings attacks closer to becoming practical.

Beyond actually breaking through the cipher, some attacks involve gaining access to information used to encrypt and decrypt, such as obtaining a key from a side-channel attack. These attacks are more practical as the difficulty of this attack scales with how securely keys and initialization vectors are shared in a network.

## Conclusion
Considering the complexity and security of each version of AES, it is very likely this algorithm will continue to be commonly used to encrypt data. Since there is no currently conceivable way of cracking AES, it has been and will continue to be a standard in encrypting sensitive information.
