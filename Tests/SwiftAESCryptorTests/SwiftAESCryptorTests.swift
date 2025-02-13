import Testing
import CommonCrypto
@testable import SwiftAESCryptor

@Test func testAESEncryptionDecryption_CBC() async throws {
    // CBC mode test with valid key and IV strings (AES-128).
    let keyString = "1234567890abcdef"     // 16 characters (AES-128)
    let ivString = "fedcba0987654321"      // 16 characters IV for CBC mode
    let plainText = "Hello, AES encryption with key/IV as strings!"
    
    let encryptedData = try SwiftAESCryptor.encrypt(plainText: plainText,
                                                    keyString: keyString,
                                                    ivString: ivString,
                                                    usePKCS7Padding: true,
                                                    useECB: false,
                                                    keySize: kCCKeySizeAES128)
    #expect(encryptedData.isEmpty == false)
    
    let decryptedText = try SwiftAESCryptor.decryptToUtf8String(encryptedData: encryptedData,
                                                                keyString: keyString,
                                                                ivString: ivString,
                                                                usePKCS7Padding: true,
                                                                useECB: false,
                                                                keySize: kCCKeySizeAES128)
    #expect(decryptedText == plainText)
}

@Test func testAESEncryptionDecryption_ECB() async throws {
    // ECB mode test; note that IV is ignored in ECB.
    let keyString = "1234567890abcdef"
    let plainText = "Hello, AES encryption in ECB mode!"
    
    let encryptedData = try SwiftAESCryptor.encrypt(plainText: plainText,
                                                    keyString: keyString,
                                                    usePKCS7Padding: true,
                                                    useECB: true,
                                                    keySize: kCCKeySizeAES128)
    #expect(encryptedData.isEmpty == false)
    
    let decryptedText = try SwiftAESCryptor.decryptToUtf8String(encryptedData: encryptedData,
                                                                keyString: keyString,
                                                                usePKCS7Padding: true,
                                                                useECB: true,
                                                                keySize: kCCKeySizeAES128)
    #expect(decryptedText == plainText)
}

@Test func testAESEncryptionDecryption_EmptyIV_CBC() async throws {
    // CBC mode test where an empty IV string is provided.
    let keyString = "1234567890abcdef"
    let plainText = "Hello, AES encryption with empty IV!"
    
    let encryptedData = try SwiftAESCryptor.encrypt(plainText: plainText,
                                                    keyString: keyString,
                                                    usePKCS7Padding: true,
                                                    useECB: false,
                                                    keySize: kCCKeySizeAES128)
    #expect(encryptedData.isEmpty == false)
    
    let decryptedText = try SwiftAESCryptor.decryptToUtf8String(encryptedData: encryptedData,
                                                                keyString: keyString,
                                                                usePKCS7Padding: true,
                                                                useECB: false,
                                                                keySize: kCCKeySizeAES128)
    #expect(decryptedText == plainText)
}

@Test func testInvalidKeySize() async throws {
    // Test that providing an invalid key size results in an error.
    let keyString = "shortkey"             // Invalid: too short for AES-128
    let ivString = "fedcba0987654321"
    let plainText = "Test text"
    
    
    #expect(throws: AESError.invalidKeySize(expected: kCCKeySizeAES128 ,actual: keyString.count)) {
        try SwiftAESCryptor.encrypt(plainText: plainText,
                                    keyString: keyString,
                                    ivString: ivString,
                                    usePKCS7Padding: true,
                                    useECB: false,
                                    keySize: kCCKeySizeAES128)
    }
}

@Test func testInvalidIVSize() async throws {
    // Test that providing an invalid IV size in CBC mode results in an error.
    let keyString = "1234567890abcdef"
    let ivString = "shortiv"               // Invalid: too short (should be 16 bytes)
    let plainText = "Test text"
    
    #expect(throws: AESError.invalidIVSize(expected: kCCBlockSizeAES128, actual: ivString.count)) {
        try SwiftAESCryptor.encrypt(plainText: plainText,
                                    keyString: keyString,
                                    ivString: ivString,
                                    usePKCS7Padding: true,
                                    useECB: false,
                                    keySize: kCCKeySizeAES128)
    }
}

@Test func testAES256EncryptionDecryption() async throws {
    // Test using AES-256 encryption/decryption.
    let keyString = "1234567890abcdef1234567890abcdef" // 32 characters (AES-256)
    let ivString = "fedcba0987654321"                   // 16 characters IV
    let plainText = "Hello, AES-256 encryption!"
    
    let encryptedData = try SwiftAESCryptor.encrypt(plainText: plainText,
                                                    keyString: keyString,
                                                    ivString: ivString,
                                                    usePKCS7Padding: true,
                                                    useECB: false,
                                                    keySize: kCCKeySizeAES256)
    #expect(encryptedData.isEmpty == false)
    
    let decryptedText = try SwiftAESCryptor.decryptToUtf8String(encryptedData: encryptedData,
                                                                keyString: keyString,
                                                                ivString: ivString,
                                                                usePKCS7Padding: true,
                                                                useECB: false,
                                                                keySize: kCCKeySizeAES256)
    #expect(decryptedText == plainText)
}

@Test func testNoPaddingValidPlaintext() async throws {
    // Test encryption/decryption with no padding.
    // Plaintext must be an exact multiple of the block size (16 bytes for AES).
    let keyString = "1234567890abcdef"
    let ivString = "fedcba0987654321"
    let plainText = "ABCDEFGHIJKLMNOP"   // 16 ASCII characters
    let usePKCS7Padding = false
    
    let encryptedData = try SwiftAESCryptor.encrypt(plainText: plainText,
                                                    keyString: keyString,
                                                    ivString: ivString,
                                                    usePKCS7Padding: usePKCS7Padding,
                                                    useECB: false,
                                                    keySize: kCCKeySizeAES128)
    #expect(encryptedData.count == 16)
    
    let decryptedText = try SwiftAESCryptor.decryptToUtf8String(encryptedData: encryptedData,
                                                                keyString: keyString,
                                                                ivString: ivString,
                                                                usePKCS7Padding: usePKCS7Padding,
                                                                useECB: false,
                                                                keySize: kCCKeySizeAES128)
    #expect(decryptedText == plainText)
}

@Test func testComparsionFromSite() async throws {
    let keyString = "1234567890abcdef"
    let plainText = "HELLO AES CRYPTO, hello aes crypto, https://www.javainuse.com/aesgenerator"
    let encryptedBase64StringFromSite = "UIzonVJEIohCqDbbZ/bWFv0p25+in24gxCb33wYWml0fjhXw33J81SljhabyIknCazY8QrLPafXHILIMfkq6LyLUbMQaUMZvZg+63L0pRJg="
    
    let encryptedString = try SwiftAESCryptor.encryptToBase64String(plainText: plainText,
                                                                    keyString: keyString,
                                                                    useECB: true,
                                                                    keySize: kCCKeySizeAES128)
    #expect(encryptedString == encryptedBase64StringFromSite)
    
    let decryptedString = try SwiftAESCryptor.decryptToUtf8String(base64String: encryptedBase64StringFromSite,
                                                                  keyString: keyString,
                                                                  useECB: true,
                                                                  keySize: kCCKeySizeAES128)
    #expect(decryptedString == plainText)
}
