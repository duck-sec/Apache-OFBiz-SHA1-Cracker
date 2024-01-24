# Apache-OFBiz-SHA1-Cracker

This script uses python hashlib to brute force Apache OFBiz SHA1 hashes.


## Description

This is essentially a simple reverse engineer of the java used to generate the string in the first place:

``` java
 public static String cryptBytes(String hashType, String salt, byte[] bytes) {
        if (hashType == null) {
            hashType = "SHA";
        }
        if (salt == null) {
            salt = RandomStringUtils.random(new SecureRandom().nextInt(15) + 1, CRYPT_CHAR_SET);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("$").append(hashType).append("$").append(salt).append("$");
        sb.append(getCryptedBytes(hashType, salt, bytes));
        return sb.toString();
    }

    private static String getCryptedBytes(String hashType, String salt, byte[] bytes) {
        try {
            MessageDigest messagedigest = MessageDigest.getInstance(hashType);
            messagedigest.update(salt.getBytes(UtilIO.getUtf8()));
            messagedigest.update(bytes);
            return Base64.encodeBase64URLSafeString(messagedigest.digest()).replace('+', '.');
        } catch (NoSuchAlgorithmException e) {
            throw new GeneralRuntimeException("Error while comparing password", e);
        }
    }
```

## Prerequisites

Before running the exploit script, ensure that you have:

- Python 3.x installed on your system.
- An Apache OFBiz hash in the format '$TYPE$SALT$HASH'



## Usage

```
usage: OFBiz-crack.py [-h] --hash-string HASH_STRING [--wordlist WORDLIST]
```

## Example

```

$python3 OFBiz-crack.py --hash-string '$SHA1$d$F_kthjQD8fhzOOl9K9ueEBamX7g=' --wordlist /usr/share/wordlists/rockyou.txt
[+] Attempting to crack....
Found Password: tigger
hash: $SHA1$d$F_kthjQD8fhzOOl9K9ueEBamX7g=
(Attempts: 25)
[!] Super, I bet you could log into something with that!

```

## Disclaimer
This code is provided for educational and ethical security testing purposes only. It should be used responsibly and only in environments where explicit authorization has been granted. Unauthorized or malicious use is strictly prohibited. By using this code, you agree to adhere to all applicable laws, regulations, and ethical standards applicable in your jurisdiction. The creators and contributors disclaim any liability for any damages or consequences arising from the misuse or unauthorized use of this code.
