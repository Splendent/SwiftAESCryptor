// The Swift Programming Language
// https://docs.swift.org/swift-book

import Foundation
import CommonCrypto

/// Error types for AES operations.
enum AESError: Error, Equatable {
    case inputToDataConversionFailed
    case ivToDataConversionFailed
    case keyToDataConversionFailed
    case outputToStringConversionFailed
    case encryptionFailed(status: CCCryptorStatus)
    case decryptionFailed(status: CCCryptorStatus)
    case invalidKeySize(expected: Int, actual: Int)
    case invalidIVSize(expected: Int, actual: Int)
}

public struct SwiftAESCryptor {
    /**
     Encrypts the given data using AES encryption.
     
     This function performs AES encryption on the provided data using the specified key and initialization vector (IV). The encryption operation can be configured to use PKCS7 padding and/or ECB mode.
     
     - Parameters:
     - dataToEncrypt: The data that will be encrypted.
     - keyData: The encryption key as data. Its length must exactly match `keySize`.
     - ivData: The initialization vector (IV) for CBC mode. This parameter is ignored if ECB mode is enabled.
     - usePKCS7Padding: A Boolean flag indicating whether to use PKCS7 padding. Defaults to `true`.
     - useECB: A Boolean flag indicating whether to use ECB mode. Defaults to `false` (CBC mode is assumed).
     - keySize: The expected size of the key in bytes. Defaults to `kCCKeySizeAES128`.
     
     - Returns: The encrypted data.
     
     - Throws:
     - `AESError.invalidKeySize` if the key's size does not equal `keySize`.
     - `AESError.invalidIVSize` if the IV's size is not equal to `kCCBlockSizeAES128` when using CBC mode.
     - `AESError.encryptionFailed` if the encryption operation fails.
     */
    public static func encrypt(dataToEncrypt: Data,
                               keyData: Data,
                               ivData: Data?,
                               usePKCS7Padding: Bool = true,
                               useECB: Bool = false,
                               keySize: Int = kCCKeySizeAES128) throws -> Data {
        // Validate key length.
        guard keyData.count == keySize else {
            throw AESError.invalidKeySize(expected: keySize, actual: keyData.count)
        }
        
        // For CBC mode, if IV is provided then validate its size.
        if !useECB, let ivData = ivData {
            guard ivData.count == kCCBlockSizeAES128 else {
                throw AESError.invalidIVSize(expected: kCCBlockSizeAES128, actual: ivData.count)
            }
        }
        
        // Build options bitmask.
        var options: CCOptions = 0
        if usePKCS7Padding {
            options |= CCOptions(kCCOptionPKCS7Padding)
        }
        if useECB {
            options |= CCOptions(kCCOptionECBMode)
        }
        
        // Allocate output buffer.
        let bufferSize = dataToEncrypt.count + kCCBlockSizeAES128
        var buffer = Data(count: bufferSize)
        var numBytesEncrypted: size_t = 0
        
        // Perform encryption.
        let cryptStatus = buffer.withUnsafeMutableBytes { bufferBytes in
            dataToEncrypt.withUnsafeBytes { dataBytes in
                // For CBC mode, pass the IV pointer if available; for ECB mode, IV is ignored.
                let ivPointer: UnsafeRawPointer? = (!useECB ? ivData?.withUnsafeBytes { $0.baseAddress } : nil)
                return keyData.withUnsafeBytes { keyBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),          // Operation: Encrypt
                        CCAlgorithm(kCCAlgorithmAES128),    // Algorithm: AES
                        options,                          // Options: padding and/or ECB mode
                        keyBytes.baseAddress,             // Encryption key pointer
                        keySize,                          // Key length
                        ivPointer,                        // IV pointer (or nil)
                        dataBytes.baseAddress,            // Input data pointer
                        dataToEncrypt.count,              // Input data length
                        bufferBytes.baseAddress,          // Output buffer pointer
                        bufferSize,                       // Output buffer size
                        &numBytesEncrypted)               // Number of bytes encrypted
                }
            }
        }
        
        guard cryptStatus == kCCSuccess else {
            throw AESError.encryptionFailed(status: cryptStatus)
        }
        
        // Trim output buffer to actual encrypted data length.
        buffer.removeSubrange(numBytesEncrypted..<buffer.count)
        return buffer
    }
    
    /**
     Decrypts the given AES-encrypted data.
     
     This function decrypts the provided data using AES decryption with the specified key and initialization vector (IV). It supports both PKCS7 padding and ECB/CBC modes.
     
     - Parameters:
     - encryptedData: The AES-encrypted data to be decrypted.
     - keyData: The decryption key as data. Its length must exactly match `keySize`.
     - ivData: The initialization vector (IV) for CBC mode decryption. Defaults to a zeroed IV and is ignored in ECB mode.
     - usePKCS7Padding: A Boolean flag indicating whether PKCS7 padding was used during encryption. Defaults to `true`.
     - useECB: A Boolean flag indicating whether ECB mode was used. Defaults to `false` (CBC mode is assumed).
     - keySize: The expected size of the key in bytes. Defaults to `kCCKeySizeAES128`.
     
     - Returns: The decrypted data.
     
     - Throws:
     - `AESError.invalidKeySize` if the key's size is incorrect.
     - `AESError.invalidIVSize` if the IV's size is not equal to `kCCBlockSizeAES128` when using CBC mode.
     - `AESError.decryptionFailed` if the decryption operation fails.
     */
    public static func decrypt(encryptedData: Data,
                               keyData: Data,
                               ivData: Data = Data(count: kCCBlockSizeAES128),
                               usePKCS7Padding: Bool = true,
                               useECB: Bool = false,
                               keySize: Int = kCCKeySizeAES128) throws -> Data {
        
        // Validate key length.
        guard keyData.count == keySize else {
            throw AESError.invalidKeySize(expected: keySize, actual: keyData.count)
        }
        
        // For CBC mode, if IV is provided then validate its size.
        if !useECB{
            guard ivData.count == kCCBlockSizeAES128 else {
                throw AESError.invalidIVSize(expected: kCCBlockSizeAES128, actual: ivData.count)
            }
        }
        
        // Build options bitmask.
        var options: CCOptions = 0
        if usePKCS7Padding {
            options |= CCOptions(kCCOptionPKCS7Padding)
        }
        if useECB {
            options |= CCOptions(kCCOptionECBMode)
        }
        
        // Allocate output buffer.
        let bufferSize = encryptedData.count + kCCBlockSizeAES128
        var buffer = Data(count: bufferSize)
        var numBytesDecrypted: size_t = 0
        
        // Perform decryption.
        let cryptStatus = buffer.withUnsafeMutableBytes { bufferBytes in
            encryptedData.withUnsafeBytes { encryptedBytes in
                let ivPointer: UnsafeRawPointer? = (!useECB ? ivData.withUnsafeBytes { $0.baseAddress } : nil)
                return keyData.withUnsafeBytes { keyBytes in
                    CCCrypt(
                        CCOperation(kCCDecrypt),          // Operation: Decrypt
                        CCAlgorithm(kCCAlgorithmAES128),    // Algorithm: AES
                        options,                          // Options: padding and/or ECB mode
                        keyBytes.baseAddress,             // Decryption key pointer
                        keySize,                          // Key length
                        ivPointer,                        // IV pointer (or nil)
                        encryptedBytes.baseAddress,       // Input (encrypted) data pointer
                        encryptedData.count,              // Input data length
                        bufferBytes.baseAddress,          // Output buffer pointer
                        bufferSize,                       // Output buffer size
                        &numBytesDecrypted)               // Number of bytes decrypted
                }
            }
        }
        
        guard cryptStatus == kCCSuccess else {
            throw AESError.decryptionFailed(status: cryptStatus)
        }
        
        // Trim output buffer to actual decrypted data length.
        buffer.removeSubrange(numBytesDecrypted..<buffer.count)
        
        return buffer
    }
}

extension SwiftAESCryptor {
    /**
     Encrypts a plaintext string using AES encryption.
     
     This function converts the provided plaintext string to UTF‑8 encoded data and encrypts it using the specified key and IV. It internally calls the data-based `encrypt(dataToEncrypt:keyData:ivData:usePKCS7Padding:useECB:keySize:)` function.
     
     - Parameters:
     - plainText: The plaintext string to be encrypted.
     - keyData: The encryption key as data.
     - ivData: The initialization vector (IV) for CBC mode encryption. This parameter is ignored if ECB mode is enabled.
     - usePKCS7Padding: A Boolean flag indicating whether to use PKCS7 padding. Defaults to `true`.
     - useECB: A Boolean flag indicating whether to use ECB mode. Defaults to `false`.
     - keySize: The expected key size in bytes. Defaults to `kCCKeySizeAES128`.
     
     - Returns: The encrypted data.
     
     - Throws: An `AESError` if the string-to-data conversion or encryption fails.
     
     - Note: The plaintext is converted to data using UTF‑8 encoding. Ensure that the input string is valid UTF‑8 to prevent data loss.
     */
    public static func encrypt(plainText: String,
                               keyData: Data,
                               ivData: Data?,
                               usePKCS7Padding: Bool = true,
                               useECB: Bool = false,
                               keySize: Int = kCCKeySizeAES128) throws -> Data {
        
        
        // Convert plaintext to Data.
        guard let dataToEncrypt = plainText.data(using: .utf8) else {
            throw AESError.inputToDataConversionFailed
        }
        
        return try encrypt(dataToEncrypt: dataToEncrypt,
                           keyData: keyData,
                           ivData: ivData,
                           usePKCS7Padding: usePKCS7Padding,
                           useECB: useECB,
                           keySize: keySize)
    }
    
    /**
     Encrypts a plaintext string using AES encryption with key and IV provided as strings.
     
     This function converts the plaintext, key, and (optionally) IV strings to UTF‑8 encoded data and encrypts the plaintext using AES. It delegates to the string-data encryption method.
     
     - Parameters:
     - plainText: The plaintext string to encrypt.
     - keyString: The encryption key as a string. The resulting data must have a length equal to `keySize`.
     - ivString: An optional string for the initialization vector (IV). If omitted, a default zeroed IV is used.
     - usePKCS7Padding: A Boolean flag indicating whether to use PKCS7 padding. Defaults to `true`.
     - useECB: A Boolean flag indicating whether to use ECB mode. Defaults to `false`.
     - keySize: The expected key size in bytes. Defaults to `kCCKeySizeAES128`.
     
     - Returns: The encrypted data.
     
     - Throws: An `AESError` if any string-to-data conversion fails or if encryption fails.
     
     - Note: All string inputs are converted to data using UTF‑8 encoding. Ensure that the provided strings are valid UTF‑8 to avoid data loss.
     */
    public static func encrypt(plainText: String,
                               keyString: String,
                               ivString: String? = nil,
                               usePKCS7Padding: Bool = true,
                               useECB: Bool = false,
                               keySize: Int = kCCKeySizeAES128) throws -> Data {
        
        // Convert key string to Data.
        guard let keyData = keyString.data(using: .utf8) else {
            throw AESError.keyToDataConversionFailed
        }
        
        let ivData = ivString?.data(using: .utf8) ?? Data(count: kCCBlockSizeAES128)
        
        return try encrypt(plainText: plainText,
                           keyData: keyData,
                           ivData: ivData,
                           usePKCS7Padding: usePKCS7Padding,
                           useECB: useECB,
                           keySize: keySize)
    }
    
    /**
     Encrypts a plaintext string using AES encryption and returns a Base64-encoded string.
     
     This function encrypts the provided plaintext (using key and IV strings to UTF‑8 encoded data) and then converts the resulting encrypted data into a Base64-encoded string.
     
     - Parameters:
     - plainText: The plaintext string to encrypt.
     - keyString: The encryption key as a string.
     - ivString: An optional string for the initialization vector (IV). Defaults to a zeroed IV if not provided.
     - usePKCS7Padding: A Boolean flag indicating whether to use PKCS7 padding. Defaults to `true`.
     - useECB: A Boolean flag indicating whether to use ECB mode. Defaults to `false`.
     - keySize: The expected key size in bytes. Defaults to `kCCKeySizeAES128`.
     
     - Returns: A Base64-encoded string representing the encrypted data.
     
     - Throws: An `AESError` if string-to-data conversion or encryption fails.
     
     - Note: The plaintext and key are converted using UTF‑8 encoding before encryption, and the output is Base64 encoded. Conversions between Base64 and UTF‑8 may result in data loss if not handled carefully.
     */
    public static func encryptToBase64String(plainText: String,
                                             keyString: String,
                                             ivString: String? = nil,
                                             usePKCS7Padding: Bool = true,
                                             useECB: Bool = false,
                                             keySize: Int = kCCKeySizeAES128) throws -> String {
        
        // Encrypt the plaintext using the wrapper that accepts key and IV as strings.
        let encryptedData = try encrypt(plainText: plainText,
                                        keyString: keyString,
                                        ivString: ivString,
                                        usePKCS7Padding: usePKCS7Padding,
                                        useECB: useECB,
                                        keySize: keySize)
        // Convert the encrypted Data to a Base64 encoded string.
        return encryptedData.base64EncodedString()
    }
}

extension SwiftAESCryptor {
    /**
     Decrypts AES-encrypted data to a UTF‑8 string using a key provided as a string.
     
     This function converts the key string to data, decrypts the given AES-encrypted data, and returns the resulting plaintext as a UTF‑8 encoded string.
     
     - Parameters:
     - encryptedData: The AES-encrypted data.
     - keyString: The decryption key as a string.
     - ivString: An optional string for the initialization vector (IV). Defaults to a zeroed IV if not provided.
     - usePKCS7Padding: A Boolean flag indicating whether PKCS7 padding was used during encryption. Defaults to `true`.
     - useECB: A Boolean flag indicating whether ECB mode was used. Defaults to `false`.
     - keySize: The expected key size in bytes. Defaults to `kCCKeySizeAES128`.
     
     - Returns: The decrypted UTF‑8 string.
     
     - Throws: An `AESError` if string-to-data conversion or decryption fails.
     
     - Note: The decryption result is assumed to be valid UTF‑8. If the decrypted data is not valid UTF‑8, conversion to a string may fail or result in data loss.
     */
    public static func decryptToUtf8String(encryptedData: Data,
                                           keyString: String,
                                           ivString: String? = nil,
                                           usePKCS7Padding: Bool = true,
                                           useECB: Bool = false,
                                           keySize: Int = kCCKeySizeAES128) throws -> String {
        
        // Convert key string to Data.
        guard let keyData = keyString.data(using: .utf8) else {
            throw AESError.keyToDataConversionFailed
        }
        
        let ivData = try {
            guard let ivString = ivString else {
                return Data(count: kCCBlockSizeAES128)
            }
            guard let data = ivString.data(using: .utf8) else {
                throw AESError.ivToDataConversionFailed
            }
            return data
        }()
        
        let decryptedData = try decrypt(encryptedData: encryptedData,
                                        keyData: keyData,
                                        ivData: ivData,
                                        usePKCS7Padding: usePKCS7Padding,
                                        useECB: useECB,
                                        keySize: keySize)
        
        // Convert decrypted Data to a UTF‑8 String.
        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw AESError.outputToStringConversionFailed
        }
        
        return decryptedString
    }
    
    /**
     Decrypts a Base64-encoded AES-encrypted string to a UTF‑8 string.
     
     This function first decodes the Base64-encoded string to retrieve the AES-encrypted data, then decrypts the data using the provided key and IV strings, and finally converts the decrypted data to a UTF‑8 encoded string.
     
     - Parameters:
     - base64String: A Base64-encoded string representing the AES-encrypted data.
     - keyString: The decryption key as a string.
     - ivString: An optional string for the initialization vector (IV). Defaults to a zeroed IV if not provided.
     - usePKCS7Padding: A Boolean flag indicating whether PKCS7 padding was used during encryption. Defaults to `true`.
     - useECB: A Boolean flag indicating whether ECB mode was used. Defaults to `false`.
     - keySize: The expected key size in bytes. Defaults to `kCCKeySizeAES128`.
     
     - Returns: The decrypted UTF‑8 string.
     
     - Throws: An `AESError` if Base64 decoding, string-to-data conversion, or decryption fails.
     
     - Note: This function involves both Base64 decoding and UTF‑8 conversion. Ensure that the Base64 string is valid and that the decrypted data is correctly encoded in UTF‑8 to avoid data loss.
     */
    public static func decryptToUtf8String(base64String: String,
                                           keyString: String,
                                           ivString: String? = nil,
                                           usePKCS7Padding: Bool = true,
                                           useECB: Bool = false,
                                           keySize: Int = kCCKeySizeAES128) throws -> String {
        
        // Decode the Base64 string to obtain the encrypted Data.
        guard let encryptedData = Data(base64Encoded: base64String) else {
            throw AESError.inputToDataConversionFailed
        }
        
        // Decrypt the data using the wrapper function that accepts key and IV as strings.
        let decryptedString = try decryptToUtf8String(encryptedData: encryptedData,
                                                      keyString: keyString,
                                                      ivString: ivString,
                                                      usePKCS7Padding: usePKCS7Padding,
                                                      useECB: useECB,
                                                      keySize: keySize)
        return decryptedString
    }
}
