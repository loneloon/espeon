# Espeon

🧤*Light keyword-based encryption algorithm.*🧤

### Description

Espeon encryption service exposes two methods: encrypt/decrypt. Before returning the output encrypt will validate the encrypted string to verify that it can be decrypted safely back to source. Encryption algorithm is based off of provided ecryption key.

Encryption logic is as follows:

- Encrypted string is split into characters
- Individual characters are converted into their respective UTF16 codepoints.
- Codepoints are split into digits. Each digit is translated into a character from the provided encryption key using value as positional index in that string.
- Individual translations are joined together into a master string using last character of the encryption key as a separator.

### Usage

Espeon encryption should be used **ONLY** as a **SECONDARY** layer on top of another **SECURE** hashing algorithm (i.e. Bcrypt, Scrypt, SHA512, Argon2).

```
const encryptionKey = "~Esp3eo0Nn-"


const encryptionService = new Espeon(encryptionKey)

const hashedString = bcrypt.hash(sensitiveString, 10)
const doubleEncryptedString = encryptionService.encrypt(hashedString)
```
