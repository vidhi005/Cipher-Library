import ast
import streamlit as st
import json  # Import the json module


# Functions for various ciphers
from ciphers import *

json_file_path = os.path.join(os.path.dirname(current_path), "cipher_info.json")


# Function to store cipher information in a JSON file
def store_cipher_info(text, cipher_name, key, rounds):
    cipher_info = {"Cipher": cipher_name, "Key": key, "Text": text, "Round": rounds}
    try:
        with open(json_file_path, "r") as file:
            existing_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_data = []
    existing_data.append(cipher_info)
    with open(json_file_path, "w") as file:
        json.dump(existing_data, file, indent=4)


def decrypt_text(cipher_text, cipher_name, key, rounds):
    result=cipher_text
    while (rounds>0):
        if cipher_name == "Caesar Cipher":
            result = caesar_cipher(result, key, mode="decrypt")
        elif cipher_name == "Playfair Cipher":
            result = playfair_cipher(result, key, mode="decrypt")
        elif cipher_name == "Vigenere Cipher":
            result = vigenere_cipher(result, key, mode="decrypt")
        elif cipher_name == "Rail Fence Cipher":
            result = rail_fence_cipher(result, key, mode="decrypt")
        elif cipher_name == "Columnar Cipher":
            result = columnar_cipher(result, key, mode="decrypt")
        elif cipher_name == "RSA":
            result = rsa_confidentiality_signature(mode="decrypt")
        else:
            result = result
        rounds=rounds-1
        print(rounds)
    return result


def encrypt_text(text, cipher_name, key, rounds=3):
    encrypted_text = text
    for _ in range(rounds):
        if cipher_name == "Caesar Cipher":
            encrypted_text = caesar_cipher(encrypted_text, key, mode="encrypt")
        elif cipher_name == "Playfair Cipher":
            encrypted_text = playfair_cipher(encrypted_text, key, mode="encrypt")
        elif cipher_name == "Vigenere Cipher":
            encrypted_text = vigenere_cipher(encrypted_text, key, mode="encrypt")
        elif cipher_name == "Rail Fence Cipher":
            encrypted_text = rail_fence_cipher(encrypted_text, key, mode="encrypt")
        elif cipher_name == "Columnar Cipher":
            encrypted_text = columnar_cipher(encrypted_text, key, mode="encrypt")
        elif cipher_name == "RSA":
            encrypted_text, key, encrypted_text_ord = rsa_confidentiality_signature(
                encrypted_text, mode="encrypt"
            )
        else:
            break  # Exit if an unsupported cipher is selected
    store_cipher_info(encrypted_text, cipher_name, key, rounds)
    return encrypted_text



# Streamlit UI
# Streamlit UI
st.title("Cipher Library")

operation = st.sidebar.selectbox("Select Operation", ["Encrypt", "Decrypt"])
text = st.text_area("Enter Text:")

if operation == "Encrypt":
    cipher_name = st.selectbox(
        "Select Cipher",
        [
            "Caesar Cipher",
            "Playfair Cipher",
            "Vigenere Cipher",
            "Rail Fence Cipher",
            "Columnar Cipher",
            "RSA",
        ],
    )
    if cipher_name != "RSA":
        key = st.text_input("Enter Key:")
    else:
        key = None
    rounds = st.number_input("Number of Encryption Rounds", min_value=1, max_value=10, value=1)
    if st.button("Encrypt"):
        encrypted_text = text
        if cipher_name != "None":
            encrypted_text = encrypt_text(encrypted_text, cipher_name, key, rounds)
        st.success(f"Encrypted Text: {encrypted_text}")


if operation == "Decrypt":
    cipher_info = st.file_uploader(
        "Upload Cipher Information File", type=["json"]
    )  # Update file type to JSON
    if cipher_info:
        cipher_data = json.load(cipher_info)  # Load JSON data
        loaded_text = text
        decrypted_text = ""
        for info in reversed(cipher_data):
            cipher_name = info["Cipher"]
            key = info["Key"]
            cipher_text = info["Text"]
            rounds=info["Round"]
            if cipher_name != "RSA":
                if loaded_text == cipher_text:
                    decrypted_text = decrypt_text(cipher_text, cipher_name, key, rounds)
                    break
                else:
                    continue
            else:
                # loaded_text = ast.literal_eval(loaded_text)
                try:
                    loaded_txt_list = ast.literal_eval(loaded_text)
                except Exception as e:
                    loaded_txt_list = [ord(i) for i in loaded_text]
                if compare_lists(loaded_txt_list, cipher_text):
                    private_key_sndr = key["Private Key Sender"]
                    public_key_rcvr = key["Public Key Receiver"]
                    n_ = key["n"]
                    siganature_ = key["Signature"]
                    decrypted_text = decrypt_rsa(
                        siganature_, cipher_text, private_key_sndr, public_key_rcvr, n_
                    )
                    break
                else:
                    continue

        if decrypted_text:
            st.success(f"Decrypted Text: {decrypted_text}")
        else:
            st.text("No cipher information found")