"""
Use a hash generator with API. This hides passwords
You only need the first five Hashed code numbers. This is more secure way of protecting user passwords.
"""

import requests
# Used to request data
import hashlib
# Used to hash data
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}', 'check the api and re-try.')
    return response


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    # ^^ Splits the hash at the ':' which separates the hash and the count
    for h, count in hashes:
        if h == hash_to_check:
            # If the hash is equal to remaining chars
            return count
    return 0


def pwn_api_check(password):
    # Check if password exists in api response.
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()  # Encodes and converts to hash
    first5_char, remaining_chars = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, remaining_chars)


def main(args):
    for password in args:
        count = pwn_api_check(password)
        if count:
            print(f'{password} was found {count} times....you should probably change that.')
        else:
            print(f'{password} was not found. Carry on!')
    return 'Done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))  
    # Exits the program 
