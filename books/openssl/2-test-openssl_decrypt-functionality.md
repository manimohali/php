
To test the functionality of `openssl_decrypt()` on your server at `http://server-2.local/`, we can create a use case that simulates encrypting sensitive data (e.g., a user password or an API token) and then decrypting it.

Here’s a step-by-step example use case, where:
1. You **encrypt data** on the server (e.g., when a user registers or submits sensitive information).
2. You **decrypt data** (e.g., when verifying or retrieving the data securely).

### Step 1: Encrypting Data (Using `openssl_encrypt`)

First, create a PHP script (`encrypt.php`) that encrypts data using OpenSSL. This script will simulate encrypting sensitive data, such as a password or secret token.

#### Example: `encrypt.php`
```php
<?php
// The data we want to encrypt (e.g., a password or token)
$data = "super_secret_password";

// The encryption method (AES-256-CBC)
$method = "AES-256-CBC";

// Generate a random encryption key (must be 32 bytes for AES-256)
$key = openssl_random_pseudo_bytes(32);

// Generate a random Initialization Vector (must be 16 bytes for AES-256-CBC)
$iv = openssl_random_pseudo_bytes(16);

// Encrypt the data
$encrypted_data = openssl_encrypt(
    $data,              // The data to encrypt
    $method,            // The encryption method
    $key,               // The secret key
    OPENSSL_RAW_DATA,   // Use raw binary data
    $iv                 // The initialization vector (IV)
);

// Encode the encrypted data and IV for safe storage or transmission
$encrypted_data_base64 = base64_encode($encrypted_data);
$iv_base64 = base64_encode($iv);
$key_base64 = base64_encode($key);

// Output the encrypted data and IV
echo "Encrypted data: $encrypted_data_base64\n";
echo "IV: $iv_base64\n";
echo "Key: $key_base64\n";

// Optionally store the encrypted data and key in a database or file
// Store securely, the key and IV should be protected!
```

### Step 2: Decrypting Data (Using `openssl_decrypt`)

Next, create a PHP script (`decrypt.php`) that decrypts the data previously encrypted by `encrypt.php`.

#### Example: `decrypt.php`
```php
<?php
// Encrypted data, IV, and key (from the previous encryption)
$encrypted_data_base64 = "put_encrypted_data_here";
$iv_base64 = "put_iv_here";
$key_base64 = "put_key_here";

// Decode the base64-encoded data, IV, and key
$encrypted_data = base64_decode($encrypted_data_base64);
$iv = base64_decode($iv_base64);
$key = base64_decode($key_base64);

// Decrypt the data
$decrypted_data = openssl_decrypt(
    $encrypted_data,   // The encrypted data
    "AES-256-CBC",     // The encryption method
    $key,              // The secret encryption key
    OPENSSL_RAW_DATA,  // Use raw binary data
    $iv                // The initialization vector (IV)
);

// Output the decrypted data
if ($decrypted_data === false) {
    echo "Decryption failed.\n";
} else {
    echo "Decrypted data: $decrypted_data\n";
}
```

### Step 3: Test the Use Case on Your Server

1. **Deploy the Scripts**: 
   - Upload `encrypt.php` and `decrypt.php` to your server located at `http://server-2.local/`.

2. **Run the Encryption Script**:
   - Access `http://server-2.local/encrypt.php` in your browser or via `curl` to run the encryption process.
   - The script will generate and display the encrypted data, IV, and key.

   Example output:
   ```
   Encrypted data: N5oJX+eZ9vw0dQ== (this will be longer in reality)
   IV: C2FjZGVmZ2hpamtsbW5vcA==
   Key: YWFhYmJiY2NjZGRlZWZmZ2doaGhmZjEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU=
   ```

3. **Run the Decryption Script**:
   - Copy the output values from the `encrypt.php` script (the encrypted data, IV, and key) into `decrypt.php` at the respective places.
   - Access `http://server-2.local/decrypt.php` to run the decryption process.
   - The script should output the original data.

   Example output:
   ```
   Decrypted data: super_secret_password
   ```

### Use Case: When You Might Use This

1. **User Data Encryption**: 
   - You could use `openssl_encrypt()` to encrypt sensitive data, such as passwords or private user information, before storing it in a database.
   - Use `openssl_decrypt()` to retrieve and decrypt that data when necessary (e.g., during user login or when retrieving secure information).

2. **Secure API Communication**:
   - In some cases, you might want to securely send encrypted tokens between a client and server. You can encrypt sensitive data on the server using `openssl_encrypt()` and decrypt it upon receipt using `openssl_decrypt()`.

3. **File Encryption**:
   - Encrypt files before storing them on the server, and decrypt them only when needed, ensuring that even if files are compromised, they remain secure without the decryption key.

### Security Considerations:
1. **Key Storage**: The encryption key should be stored securely (e.g., in an environment variable or a secure vault), not hardcoded into your PHP code or database.
2. **Random IV**: Always use a random IV for each encryption operation, even if the same key is used, to ensure that identical data encrypted multiple times yields different ciphertexts.
3. **Encryption Methods**: AES-256-CBC is a widely used encryption method. For enhanced security, consider using authenticated encryption modes like AES-256-GCM to prevent tampering.
4. **SSL**: Ensure that the data transmission between the client and server happens over HTTPS to prevent interception.

With these steps, you can test `openssl_decrypt()` on your local server and explore encryption/decryption use cases!
