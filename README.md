# LiveCode encryption library

This library is borrowed from revIgniter's encryption library  
and includes all features as described in the revIgniter User Guide  
(please see chapter [Encryption Library](https://revigniter.com/userGuide/libraries/encryption.html)). It is meant to be used with  
desktop and mobile apps.  

### Requirements

LiveCode version 9 or higher  

### How to use this library:

#### Starting
Place the library in the message path like:  

    start using stack "path/to/encryptLib.livecodescript"

#### Setting your key
**Note:** Setting your key is different to the server version of this library, use:  

    rigSetEncryptionKey <key>
Example:  

    rigSetEncryptionKey "mySuperSecretKey"

#### Encryption and decryption

please refer to the chapter [Encryption Library](https://revigniter.com/userGuide/libraries/encryption.html) in the  
revIgniter User Guide.  

#### Setting a cipher and a hash type

please refer to the chapter [Encryption Library](https://revigniter.com/userGuide/libraries/encryption.html) in the  
revIgniter User Guide.  

##### Default values

hash type: "SHA-1"  
cipher: "bf"  
cipher key length: 128  

#### Getter
In contrast to the server version this library includes a getter:  

    rigEncryptGet(pVariableName)

This function returns the values of an array variable  
provided that a valid key name is used as parameter.  
Array key names (used as parameter) are:  

- "encryptionKey"
- "_hashType"
- "cipher"
- "cipherKeyLength"

### License

For the license terms see the LICENSE file.  

### Meta

Version: 1.0.0  
Web Site: <https://revigniter.com/>  

Author:  Ralf Bitter  
