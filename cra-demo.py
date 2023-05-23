"""
cra-demo.py
Author: Joseph Erdosy

This file contains the implementation of a challenge-response authentication system 
using QR codes and RSA encryption. It defines a class AuthenticationSystem, which represents 
the authentication system for a single user. The authentication process involves 
generating challenges, calculating checksums, verifying responses, and exchanging 
public keys using QR codes.

Usage: 
    python cra-demo.py "Test" gen
    python cra-demo.py "Test" challenge
    python cra-demo.py "Test" response
"""


import argparse
import time
import rsa
import qrcode
import string
from pyzbar.pyzbar import decode
from PIL import Image
from colorama import Fore, Style


CHARACTER_SET = string.ascii_uppercase + string.digits  # All uppercase letters and digits
QR_CODE_FILE = "qrcode.png"


class AuthenticationSystem:
    """
    Represents the challenge-response authentication system for a single user.
    """

    def __init__(self, user_name):
        """
        Initializes a new instance of the AuthenticationSystem with the given user name
        and creates a key pair using RSA encryption.

        Parameters:
            user_name (str): The name of the user.
        """
        self.user_name = user_name
        self.public_key, self.private_key = self.create_key_pair()

    def create_key_pair(self):
        """
        Generates a new RSA key pair with a key size of 512 bits and returns the public and private keys.
        """
        public_key, private_key = rsa.newkeys(512)
        return public_key, private_key

    def extract_public_key(self, qr_code_data):
        """
        Extracts the public key from the given QR code data, assuming the first 1024 characters,
        and returns the public key object.

        Parameters:
            qr_code_data (str): The QR code data containing the public key.

        Returns:
            rsa.PublicKey: The extracted public key.
        """
        key_data = qr_code_data[:1024]
        public_key = rsa.PublicKey.load_pkcs1(bytes.fromhex(key_data))
        return public_key

    def key_and_signature_to_qrcode(self, file_name):
        """
        Generates a QR code image containing the hexadecimal representations of the public and private keys
        and saves it to the specified file.

        Parameters:
            file_name (str): The name of the file to save the QR code image.
        """
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_H)
        qr.add_data(self.public_key.save_pkcs1().hex() + self.private_key.save_pkcs1().hex())
        qr.make(fit=True)
        qr_code = qr.make_image(fill='black', back_color='white')
        qr_code.save(file_name)

    def generate_response(self, challenge_with_checksum):
        """
        Generates a response to the given challenge with checksum. Converts the challenge to an integer,
        calculates the response using the private key, and converts it back to a base 36 string representation
        with the checksum.

        Parameters:
            challenge_with_checksum (str): The challenge with checksum.

        Returns:
            str: The generated response with checksum.
        """
        # Split the challenge and checksum
        parts = challenge_with_checksum.split('-')
        if len(parts) != 2:
            raise ValueError("Invalid challenge format")

        challenge, checksum = parts

        # Verify the checksum
        if checksum != self.generate_checksum(challenge):
            raise ValueError("Invalid checksum for challenge")

        # Convert the challenge from base 36 to an integer
        challenge_int = int(challenge, 36)

        # Generate a response using the challenge and private key
        response = (challenge_int * self.private_key.e) % (36 ** 6)

        # Convert the response to a string representation
        response_str = ''
        while response:
            response, remainder = divmod(response, 36)
            response_str = CHARACTER_SET[remainder] + response_str
        response_str = response_str.rjust(6, CHARACTER_SET[0])  # Pad to 6 characters

        # Append the checksum to the response
        response_with_checksum = f"{response_str}-{checksum}"
        return response_with_checksum

    def generate_checksum(self, code):
        """
        Generates a checksum for the given code using the defined character set
        and an algorithm based on the ordinal values of characters.

        Parameters:
            code (str): The code for which to generate the checksum.

        Returns:
            str: The generated checksum.
        """
        # Generate a checksum from the code
        checksum_value = sum((i + 1) * ord(char) for i, char in enumerate(code)) % 36
        return CHARACTER_SET[checksum_value]  # Convert to a character from the set

    def generate_challenge(self):
        """
        Generates a random challenge as an index into the base 36 character set.
        Converts the challenge to a base 36 string representation, pads it to 6 characters,
        calculates a checksum, and returns the challenge with checksum.

        Returns:
            str: The generated challenge with checksum.
        """
        challenge = int(time.time()) % (36 ** 6)  # This will generate an index into the base 36 set
        challenge_str = ''
        while challenge:
            challenge, remainder = divmod(challenge, 36)
            challenge_str = CHARACTER_SET[remainder] + challenge_str
        challenge_str = challenge_str.rjust(6, CHARACTER_SET[0])  # Pad to 6 characters
        checksum = self.generate_checksum(challenge_str)
        return f"{challenge_str}-{checksum}"
    
    def verify_response(self, challenge_with_checksum, response):
        """
        Verifies the response for the given challenge with checksum. Splits the challenge and checksum, verifies the checksum, extracts the response without the checksum, converts the challenge and response to integers, generates the expected response using the public key, converts the expected response to a string representation, and compares it with the extracted response. Returns True if they match, False otherwise.

        Parameters:
            challenge_with_checksum (str): The challenge with checksum.
            response (str): The response to verify.

        Returns:
            bool: True if the response is valid, False otherwise.
        """
        # Split the challenge and checksum
        parts = challenge_with_checksum.split('-')
        if len(parts) != 2:
            raise ValueError("Invalid challenge format")
        
        challenge, checksum = parts

        # Verify the checksum
        if checksum != self.generate_checksum(challenge):
            raise ValueError("Invalid checksum for challenge")

        # Extract the response without the checksum
        response_without_checksum = response.split('-')[0]

        # Convert the challenge and response from base 36 to integers
        challenge_int = int(challenge, 36)
        response_int = int(response_without_checksum, 36)
        
        # Generate the expected response using the challenge and public key
        expected_response = (challenge_int * self.public_key.e) % (36 ** 6)
        
        # Convert the expected response to a string representation
        expected_response_str = ''
        while expected_response:
            expected_response, remainder = divmod(expected_response, 36)
            expected_response_str = CHARACTER_SET[remainder] + expected_response_str
        expected_response_str = expected_response_str.rjust(6, CHARACTER_SET[0])  # Pad to 6 characters


##### Command-line argument interface #####

def generate_qr_code(user_name):
    """
    Generates the QR code for the user and saves it to a file.

    Parameters:
        user_name (str): The name of the user.
    """
    user = AuthenticationSystem(user_name)
    user.key_and_signature_to_qrcode(QR_CODE_FILE)
    print(f"{Fore.BLUE}{Style.BRIGHT}> {user_name} generated their QR Code, saved to {QR_CODE_FILE}{Style.RESET_ALL}")


def challenge_and_response(user_name):
    """
    Reads the QR code, extracts the public key, generates a challenge, and prompts for response verification.

    Parameters:
        user_name (str): The name of the user.
    """
    user = AuthenticationSystem(user_name)
    qr_code_data = read_qr_code(QR_CODE_FILE)
    public_key = user.extract_public_key(qr_code_data)
    challenge = user.generate_challenge()
    print(f"{Fore.YELLOW}{Style.BRIGHT}Challenge: {challenge}{Style.RESET_ALL}")
    response = input("Enter the response: ")
    verification_result = (response == user.generate_response(challenge))
    if verification_result:
        print(f"{Fore.GREEN}{Style.BRIGHT}Verification successful!{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}{Style.BRIGHT}Verification failed.{Style.RESET_ALL}")


def read_qr_code(file_name):
    """
    Reads the QR code image from the specified file, decodes the data, and returns it as a string or None if no data is found.

    Parameters:
        file_name (str): The name of the file containing the QR code image.

    Returns:
        str or None: The decoded data from the QR code, or None if no data is found.
    """
    # Decode the QR code from the image file
    decoded_objects = decode(Image.open(file_name))

    # Return the decoded data
    if decoded_objects:
        return decoded_objects[0].data.decode()
    else:
        return None

def generate_response(user_name, challenge):
    """
    Generates the response to the given challenge.

    Parameters:
        user_name (str): The name of the user.
        challenge (str): The challenge to respond to.
    """
    user = AuthenticationSystem(user_name)
    response = user.generate_response(challenge)
    print(f"{Fore.YELLOW}{Style.BRIGHT}Response: {response}{Style.RESET_ALL}")


def main():
    """
    Main entry point for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Challenge-Response Authentication System")
    parser.add_argument("user_name", type=str, help="Name of the user")
    parser.add_argument("command", type=str, choices=["gen", "challenge", "response"],
                        help="Command: 'gen' for generating QR code and key pair, 'challenge' for generating a challenge,"
                             "'response' for verifying a response")

    args = parser.parse_args()

    user_name = args.user_name
    command = args.command

    if command == "gen":
        generate_qr_code(user_name)
    elif command == "challenge":
        challenge_and_response(user_name)
    elif command == "response":
        challenge = input("Enter the challenge: ")
        generate_response(user_name, challenge)


if __name__ == "__main__":
    main()
