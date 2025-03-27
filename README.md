# Secure Key Management System

## Live Demo
[Run on Google Colab]()

## Understanding Code in Simple Words
Imagine you and your friend want to exchange secret messages without anyone else listening. But you need a special lock (key) that only you both can use. This program helps you:

- **Get a Personal Lock:** When you register, you get your own secret lock (encryption key).
- **Verify Your Identity:** Like an ID card, you get a certificate proving you're real.
- **Share a Common Lock:** You and your friend create a shared lock (key exchange) so you can send secure messages.
- **Send Secret Messages:** Your messages are put inside a locked box (encryption) before sending.
- **Unlock Messages Safely:** Your friend uses the same key to unlock and read the message.
- **Change Locks When Needed:** If someone steals your lock, you throw it away and get a new one (key rotation).

Think of it like sending a diary with a secret code that only you and your friend know, so no one else can read it! 

## Features
- Implements a secure key management system with encryption and key exchange.
- Supports user registration, certificate issuance, and revocation.
- Uses Diffie-Hellman key exchange for secure communication.
- Encrypts and decrypts messages with AES encryption.
- Tracks revoked keys to prevent unauthorized access.

## Prerequisites
- Install Python 3.x on your system.
- Install the required cryptographic library:
  ```bash
  pip install cryptography
  ```
- Upgrade the cryptography library if needed:
  ```bash
  pip install --upgrade cryptography
  ```
- Google Colab access (for running the script online).

## How It Works
1. **User Registration:** Each user registers and gets a unique private key and AES key.
2. **Certificate Issuance:** A digital certificate is generated for the user, signed by the system’s Certificate Authority (CA).
3. **Diffie-Hellman Key Exchange:** Users can establish a shared secret key for secure communication.
4. **Message Encryption & Decryption:** Messages are encrypted using AES with shared keys.
5. **Key & Certificate Revocation:** Users can revoke keys and certificates to maintain security.
6. **Checking Certificate Status:** The system verifies whether a certificate is valid, revoked, or expired.

## Example Usage
```bash
Enter user ID: Alice
User 'Alice' registered with key version 1.

Enter user ID: Bob
User 'Bob' registered with key version 1.

Shared key established: 3f8d2e5c4...

Enter message: Hello, Bob!
Encrypted Message (hex): 4a7b89d1...

Decrypted Message: Hello, Bob!
```

## Real-Life Applications
- **Cybersecurity:** Used for managing cryptographic keys in secure systems.
- **End-to-End Encryption:** Ensures secure messaging in apps like WhatsApp and Signal.
- **Online Banking:** Protects transactions by securely exchanging keys.
- **Enterprise Security:** Helps organizations maintain secure access control.
- **Cloud Security:** Encrypts data to prevent unauthorized access in cloud storage.

## Notes
- The system uses RSA for certificates and AES for message encryption.
- Revoked keys cannot be used again for security reasons.
- Ensure the cryptography library is updated for optimal security.

## Future Enhancements
- Implement a more efficient key rotation mechanism.
- Add support for multi-user group encryption.
- Improve user authentication with biometric verification.

## Contribution
Contributions are welcome! If you find any issues or have suggestions, feel free to create a pull request or open an issue on GitHub.

## Author
**GitHub:** [@Ragha8951](https://github.com/Ragha8951)  
**Email:** [ragha8951@gmail.com](mailto:ragha8951@gmail.com)

Thank you for visiting ❤️

