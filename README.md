# RSA-OAEP Implementation Without Crypto Libraries

## Justification
This project is an implementation of the RSA cryptographic algorithm with Optimal Asymmetric Encryption Padding (OAEP), built **without** using standard cryptography libraries. The main reasons for this development are:

1. **Deep Understanding**: Implementing the cryptographic algorithm from scratch allows a complete understanding of each step in the RSA-OAEP encryption and decryption process.

2. **Full Control**: With manual implementation, we have full control over the algorithm, enabling modifications and adjustments as needed.

3. **Educational Value**: This project serves as a learning tool to understand asymmetric cryptography concepts and secure padding techniques.

4. **Transparency**: Every step of the algorithm can be inspected and tested, providing full transparency on how the system works.

5. **Use of OAEP**: OAEP padding provides additional security compared to basic RSA implementations, protecting against various attacks such as Bleichenbacher's attack.

## User Manual


### 1. Operating the GUI
#### Key Pair Generation
- Run the <code>gui.py</code> program, it will open a window with the Encrypt tab.
- Choose the Key Generation tab at the top left of the window.
- Select the file location to save your key pair (private and public key).
- Click the <b>Generate Key Pair</b> button, and the program will start generating the key pair.
- After successful creation, you can check your selected directory.

#### Encryption

#### Decryption
- Run the <code>gui.py</code> program, it will open a window with the Encrypt tab.
- Select your encrypted file by browsing through your computer directories.
- Choose your private key file from your computer.
- Click the <b>Decrypt</b> button, and it will display a success message once the decryption process is finished.
- Check your current directory for the successfully decrypted message.

### 2. Project Structure

**TO BE ADJUSTED**
This project consists of several important files:

- `rsa.py`: Contains the core implementation of RSA and OAEP algorithms.
- `key_pair_generation.py`: CLI program for generating key pairs.
- `keygen_cli.py`: Alternative CLI for key generation.
- `keygen_gui.py`: Graphical interface for key generation.
- `gui.py`: Graphical interface for message encryption.
- `encrypt_file.py`: CLI program for encrypting files.
- `decrypt_file.py`: CLI program for decrypting files.

### 3. Technical Notes

- Implementation uses 2048-bit RSA keys.
- OAEP padding is applied using the SHA-256 hash function.
- Key formats are saved in hexadecimal representation with `e:n` or `d:n` format.
- Primality testing is implemented using the Miller-Rabin algorithm.
- Key generation may take some time as it involves finding large prime numbers.

### 5. Security

- Keep your private key safe and do not share it with others.
- For secure communication, only share your public key with parties who want to send encrypted files.
- This implementation is intended for educational purposes; for production use, it is recommended to use well-tested and audited cryptographic libraries.

### 6. Constraints

- The size of files that can be encrypted is limited by the RSA key size.
- The current encryption GUI supports **TO BE ADJUSTED, TO BE ADJUSTED, TO BE ADJUSTED**.

## System Requirements

- Python 3.6 or later
- Tkinter for the graphical interface
- No external cryptographic libraries required