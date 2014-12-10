BtcSteg (C++ version)
=====================

Improved version of [btcsteg](https://github.com/Kixunil/btcsteg).

Encrypts message and hides it into series of Bitcoin addresses. Uses scrypt as PBKDF. IV and salt for scrypt are derived from first Bitcoin address (SHA256).
Generating addresses is more efficient than in bash version.

In case of this version, I'm more confident that no suspicious metadata are added to ciphertext. But I'm still not sure. Use at your own risk!

Dependencies
------------

* libcryptopp
* libscrypt
* vanitygen (in $PATH)
