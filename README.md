# SwiftAESCryptor

## Overview
SwiftAESCryptor is a Swift utility for AES encryption and decryption. It supports:
- Data, UTF-8 string, and Base64-encoded string transformations
- Configurable PKCS7 padding or no padding
- CBC (default) or ECB modes
- Key sizes: 128, 192, 256 bits
- Comprehensive error handling via the `AESError` enum

## Features
- Data-based API:
  - `encrypt(dataToEncrypt:keyData:ivData:usePKCS7Padding:useECB:keySize:)`
  - `decrypt(encryptedData:keyData:ivData:usePKCS7Padding:useECB:keySize:)`
- String-based API:
  - `encrypt(plainText:keyString:ivString:usePKCS7Padding:useECB:keySize:)` → `Data`
  - `encryptToBase64String(plainText:keyString:ivString:usePKCS7Padding:useECB:keySize:)` → `String`
  - `decryptToUtf8String(encryptedData:keyString:ivString:usePKCS7Padding:useECB:keySize:)` → `String`
  - `decryptToUtf8String(base64String:keyString:ivString:usePKCS7Padding:useECB:keySize:)` → `String`

## Installation

### Swift Package Manager
```swift
// in your Package.swift
dependencies: [
  .package(url: "https://github.com/Splenden/SwiftAESCryptor.git", .upToNextMajor(from: "0.1.0")),
],
targets: [
  .target(
    name: "YourTargetName",
    dependencies: ["SwiftAESCryptor"]
  ),
]
```

## Usage

### Encrypt & Decrypt Data
```swift
import SwiftAESCryptor

let key = Data("1234567890abcdef".utf8)
let iv = Data("fedcba0987654321".utf8)
let plaintext = Data("Hello, AES!".utf8)

do {
    let encrypted = try SwiftAESCryptor.encrypt(dataToEncrypt: plaintext,
                                               keyData: key,
                                               ivData: iv)
    let decrypted = try SwiftAESCryptor.decrypt(encryptedData: encrypted,
                                               keyData: key,
                                               ivData: iv)
    print(String(decoding: decrypted, as: UTF8.self)) // "Hello, AES!"
} catch {
    print("AES Error: \(error)")
}
```

### String & Base64 API
```swift
let base64 = try SwiftAESCryptor.encryptToBase64String(plainText: "Secret",
                                                       keyString: "1234567890abcdef")
let decrypted = try SwiftAESCryptor.decryptToUtf8String(base64String: base64,
                                                        keyString: "1234567890abcdef")
print(decrypted) // "Secret"
```

## Running Tests
Run the test suite:
```bash
swift test
```

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
