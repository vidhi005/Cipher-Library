import os
import math
import random

#                   Globals                      #
# ------------------------------------------------#
prime = None
public_key_sender = None
private_key_sender = None
public_key_receiver = None
private_key_receiver = None
n = None
message = None
signature = None
current_path = os.path.abspath(__file__)
message_file = os.path.join(os.path.dirname(current_path), "message.txt")


def caesar_cipher(text, key, mode):
    # Define the alphabet
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    # Create a dictionary to map each character to its position in the alphabet
    char_to_position = {char: pos for pos, char in enumerate(alphabet)}

    # Ensure the key is a positive integer
    key = int(key)
    text = prepare_text(text)

    # Initialize the result variable to an empty string
    result = ""

    # Iterate through each character in the input text
    for char in text:
        if char.isalpha():  # Check if the character is a letter
            # Determine if we're encrypting or decrypting
            if mode == "encrypt":
                new_pos = (char_to_position[char] + key) % 26
            elif mode == "decrypt":
                new_pos = (char_to_position[char] - key) % 26
            else:
                raise ValueError("Invalid mode. Use 'encrypt' or 'decrypt'.")

            # Find the corresponding character in the alphabet
            new_char = alphabet[new_pos]

            # Append the new character to the result
            result += new_char
        else:
            # If the character is not a letter, leave it unchanged
            result += char

    return result


def prepare_text(text):
    # Remove spaces and convert to uppercase
    return text.replace(" ", "").upper()


def playfair_cipher(text, key, mode):
    if mode not in ["encrypt", "decrypt"]:
        raise ValueError("Mode must be 'encrypt' or 'decrypt'")

    # Create the playfair matrix

    # Prepare the plaintext by removing spaces and converting to uppercase
    text = prepare_text(text)

    # Encrypt or decrypt the plaintext
    if mode == "encrypt":
        return encrypt_playfair(text, key)
    else:
        return decrypt_playfair(text, key)


def create_playfair_matrix(key):
    key = key.replace(" ", "").upper()
    key = key.replace("J", "I")
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    matrix = []

    for char in key + alphabet:
        if char not in matrix:
            matrix.append(char)

    playfair_matrix = [matrix[i : i + 5] for i in range(0, 25, 5)]

    return playfair_matrix


def encrypt_playfair(plain_text, key):
    playfair_matrix = create_playfair_matrix(key)
    plain_text = plain_text.replace(" ", "").upper()
    plain_text = plain_text.replace("J", "I")

    # Handle double letters by adding an 'X' between them
    i = 0
    while i < len(plain_text) - 1:
        if plain_text[i] == plain_text[i + 1]:
            plain_text = plain_text[: i + 1] + "X" + plain_text[i + 1 :]
        i += 2

    if len(plain_text) % 2 != 0:
        plain_text += "X"

    cipher_text = ""
    for i in range(0, len(plain_text), 2):
        char1 = plain_text[i]
        char2 = plain_text[i + 1]
        row1, col1 = find_position(playfair_matrix, char1)
        row2, col2 = find_position(playfair_matrix, char2)

        if row1 == row2:
            cipher_text += playfair_matrix[row1][(col1 + 1) % 5]
            cipher_text += playfair_matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            cipher_text += playfair_matrix[(row1 + 1) % 5][col1]
            cipher_text += playfair_matrix[(row2 + 1) % 5][col2]
        else:
            cipher_text += playfair_matrix[row1][col2]
            cipher_text += playfair_matrix[row2][col1]

    return cipher_text


def find_position(matrix, char):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j


def decrypt_playfair(cipher_text, key):
    playfair_matrix = create_playfair_matrix(key)
    cipher_text = cipher_text.replace(" ", "").upper()
    plain_text = ""

    for i in range(0, len(cipher_text), 2):
        char1 = cipher_text[i]
        char2 = cipher_text[i + 1]
        row1, col1 = find_position(playfair_matrix, char1)
        row2, col2 = find_position(playfair_matrix, char2)

        if row1 == row2:
            plain_text += playfair_matrix[row1][(col1 - 1) % 5]
            plain_text += playfair_matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            plain_text += playfair_matrix[(row1 - 1) % 5][col1]
            plain_text += playfair_matrix[(row2 - 1) % 5][col2]
        else:
            plain_text += playfair_matrix[row1][col2]
            plain_text += playfair_matrix[row2][col1]

    return plain_text


def vigenere_cipher(text, key, mode):
    text = text.upper()
    key = key.upper()

    result = ""
    key_length = len(key)
    key_index = 0

    for char in text:
        if char.isalpha():
            # Determine the shift amount based on the key character
            shift = ord(key[key_index % key_length]) - ord("A")

            if mode == "encrypt":
                # Encryption: Shift the character forward
                encrypted_char = chr(((ord(char) - ord("A") + shift) % 26) + ord("A"))
            else:
                # Decryption: Shift the character backward
                decrypted_char = chr(((ord(char) - ord("A") - shift) % 26) + ord("A"))

            if mode == "encrypt":
                result += encrypted_char
            else:
                result += decrypted_char

            key_index += 1
        else:
            # Non-alphabetic characters are not changed
            result += char

    return result


def rail_fence_cipher(text, key, mode):
    if mode not in ["encrypt", "decrypt"]:
        raise ValueError("Mode must be 'encrypt' or 'decrypt'")
    key = int(key)

    if mode == "encrypt":
        # Encryption
        rail_fence = [[] for _ in range(key)]
        rail = 0
        direction = 1

        for char in text:
            rail_fence[rail].append(char)
            rail += direction
            if rail == key - 1 or rail == 0:
                direction *= -1
        encrypted_text = "".join(["".join(rail) for rail in rail_fence])
        return encrypted_text

    elif mode == "decrypt":
        fence = [[' ' for _ in range(len(text))] for _ in range(key)]
        rail = 0
        direction = 1

        for i in range(len(text)):
            fence[rail][i] = '*'
            rail += direction

            if rail == key - 1 or rail == 0:
                direction *= -1

        idx = 0
        for i in range(key):
            for j in range(len(text)):
                if fence[i][j] == '*' and idx < len(text):
                    fence[i][j] = text[idx]
                    idx += 1

        rail = 0
        direction = 1
        decrypted_text = []

        for i in range(len(text)):
            decrypted_text.append(fence[rail][i])
            rail += direction

            if rail == key - 1 or rail == 0:
                direction *= -1

        return "".join(decrypted_text)


def columnar_cipher(text, key, mode):
    key = prepare_text(key)

    if mode == "encrypt":
        return encrypt_columnar(text, key)
    else:
        return decrypt_columnar(text, key)


def encrypt_columnar(plainText, key):
    plainText_without_space = plainText.replace(" ", "")
    row_length = len(plainText_without_space) // len(key)
    column_len = len(key)
    plainTextArr = [[0] * column_len for _ in range(row_length)]
    char_counter = 0
    for i in range(row_length):
        for j in range(column_len):
            plainTextArr[i][j] = plainText_without_space[char_counter]
            char_counter += 1

    cipher_text = ""
    index_formation = [0] * len(key)

    tempIndex = 1
    for i in range(len(key)):
        for j in range(len(key)):
            currChar = int(key[j])
            if currChar == tempIndex:
                index_formation[i] = j
        tempIndex += 1

    for i in range(column_len):
        for j in range(row_length):
            cipher_text += plainTextArr[j][index_formation[i]]

    return cipher_text


def decrypt_columnar(cipher_text, key):
    index_formation = [0] * len(key)
    row = len(key)
    col = len(cipher_text) // len(key)
    matrix = [[""] * row for _ in range(col)]
    tempIndex = 1
    for i in range(len(key)):
        for j in range(len(key)):
            currChar = int(key[j])
            if currChar == tempIndex:
                index_formation[i] = j
        tempIndex += 1
    charCounter = 0

    for i in range(row):
        for j in range(col):
            matrix[j][index_formation[i]] = cipher_text[charCounter]
            charCounter += 1

    plain_text = ""
    for i in range(col):
        for j in range(row):
            plain_text += matrix[i][j]

    return plain_text


def _gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def _is_prime(n):
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for x in range(3, int(math.sqrt(n)) + 1, 2):
        if n % x == 0:
            return False
    return True


def _generate_prime():
    while True:
        n = random.randint(10, 100)
        if _is_prime(n):
            return n


def _generate_encryption_keys():
    global public_key_sender, private_key_sender, public_key_receiver, private_key_receiver, n, p, q
    p = _generate_prime()
    q = _generate_prime()
    phi_n = (q - 1) * (p - 1)
    while True:
        e = random.randint(3, phi_n)
        if _gcd(e, phi_n) == 1:
            public_key_sender = e
            break

    d = 0
    while True:
        d += 1
        if (d * public_key_sender) % phi_n == 1:
            private_key_sender = d
            break

    n = p * q

    while True:
        e = random.randint(3, phi_n)
        if _gcd(e, phi_n) == 1:
            public_key_receiver = e
            break

    d = 0
    while True:
        d += 1
        if (d * public_key_receiver) % phi_n == 1:
            private_key_receiver = d
            break
    return


def _encrypt_signature(signature: str):
    message = [ord(char) for char in signature]
    encrypted_sign = [pow(x, private_key_receiver, n) for x in message]
    return "".join(chr(char) for char in encrypted_sign)


def _decrypt_signature(signature: str, public_key_receiver, n):
    checked_signature = [pow(x, public_key_receiver, n) for x in signature]
    return "".join(chr(x) for x in checked_signature)


def _encrypt_message(message: str):
    mess = [ord(c) for c in message]
    encrypted_message = [pow(x, public_key_sender, n) for x in mess]
    return "".join(chr(c) for c in encrypted_message)


def _decrypt_message(message: str, private_key_sender, n):
    decrypted_message = [pow(x, private_key_sender, n) for x in message]
    return "".join(chr(c) for c in decrypted_message)


def _encode_message_to_send(message):
    global signature
    encrypted_message = _encrypt_message(message)
    signature = _encrypt_signature(encrypted_message)
    return encrypted_message


def compare_lists(list1, list2):
    if len(list1) != len(list2):
        return False
    for i in range(len(list1)):
        if list1[i] != list2[i]:
            return False
    return True


def _decode_both_message_and_signature(signature, received_message, private_key_sender, public_key_receiver, n):
    decrypted_sign = [ord(c) for c in _decrypt_signature(signature, public_key_receiver, n)]
    assert compare_lists(
        received_message, decrypted_sign
    ), f"Received an incorect signature {decrypted_sign} != {received_message}"
    plain_text = _decrypt_message(received_message, private_key_sender, n)
    return plain_text

def decrypt_rsa(sign, received_message, private_key_sender, public_key_receiver, n):
    return _decode_both_message_and_signature(sign, received_message, private_key_sender, public_key_receiver, n)

def rsa_confidentiality_signature(message, mode):
    global signature
    assert mode == "encrypt", f"Mode must be 'encrypt'"
    _generate_encryption_keys()
    if mode == "encrypt":
        text = _encode_message_to_send(message)
        text_ord = [ord(c) for c in text]
        key = {
            "Private Key Sender": private_key_sender,
            "Public Key Receiver": public_key_receiver,
            "n": n,
            "Signature": [ord(c) for c in signature],
        }
        return text, key, text_ord
