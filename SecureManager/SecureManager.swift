//
//  SecureManager.swift
//  SecureManager
//
//  Created by Alexey on 5/06/2016.
//  Copyright © 2016 Alexey Zhilnikov. All rights reserved.
//

import Foundation

private let kSecureManagerApplicationTag = "com.SecureManagerApplication"
private let kSecureManagerMyTestApplicationTag = "com.SecureManagerApplication.MyTest"

enum SecureManagerErrors {
    case NoError
    case NotImplemented
    case BadRequest
    case NotAvailable
    case DuplicatedItem
    case NotFound
    case AuthFailed
    case UnknownError
}

class SecureManager {
    
    static let sharedInstance: SecureManager = {
        let instance = SecureManager()
        return instance
    }()
    
    // Generate public and private key
    func generateKeyPair(completion: (error: SecureManagerErrors) -> Void) {
        
        let publicKeyParameters = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: kSecureManagerApplicationTag
        ]
        
        let privateKeyParameters = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: kSecureManagerApplicationTag
        ]
        
        let keysParameters = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 4096,
            kSecPublicKeyAttrs as String: publicKeyParameters,
            kSecPrivateKeyAttrs as String: privateKeyParameters
        ]
        
        // References to public and private key
        var publicKey, privateKey: SecKeyRef?
        
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), {
            // Generate keys
            let status = SecKeyGeneratePair(keysParameters, &publicKey, &privateKey)
            
            dispatch_async(dispatch_get_main_queue(), {
                [unowned self] in
                // Check the result
                completion(error: self.checkStatus(status))
            })
        })
    }
    
    // Store public key in Keychain
    func storePublicKey(keyData: NSData) -> SecureManagerErrors {
        
        let keyParameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: kSecureManagerMyTestApplicationTag,
            kSecValueData as String: keyData
        ]
        
        var result: AnyObject?
        
        let status = SecItemAdd(keyParameters, &result)
        return checkStatus(status)
    }
    
    // Delete public and private keys from Keychain
    func deleteKeyPair(completion: (error: SecureManagerErrors) -> Void) {
        
        // Parameters of the keys to be deleted
        let parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: kSecureManagerApplicationTag
        ]
        
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), {
            // Delete keys
            let status = SecItemDelete(parameters)
            
            dispatch_async(dispatch_get_main_queue(), {
                [unowned self] in
                // Check the result
                completion(error: self.checkStatus(status))
            })
        })
    }
    
    // Encrypt data (NSData) with public key
    func encryptDataWithPublicKey(data: NSData,
                                  completion: (error: SecureManagerErrors, data: NSData?) -> Void) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), {
            [unowned self] in
            // Get reference to the public key
            if let publicKeyRef = self.publicKeyReference() {
                
                // Buffer for encrypted data
                guard let encryptedData = NSMutableData(length: SecKeyGetBlockSize(publicKeyRef)) else {
                    dispatch_async(dispatch_get_main_queue(), {
                        // Can't allocate memory for output data
                        completion(error: .NotAvailable, data: nil)
                    })
                    return
                }
                
                // Pointer to the data to be encrypted
                let plainText = UnsafePointer<UInt8>(data.bytes)
                let plainTextLength = data.length
                
                // Pointer to encrypted data
                let cipherText = UnsafeMutablePointer<UInt8>(encryptedData.mutableBytes)
                var cipherTextLength = encryptedData.length
                
                // Encryption
                let status = SecKeyEncrypt(publicKeyRef,
                                        .PKCS1,
                                        plainText,
                                        plainTextLength,
                                        cipherText,
                                        &cipherTextLength)
                
                dispatch_async(dispatch_get_main_queue(), {
                    [unowned self] in
                    // Encryption result
                    completion(error: self.checkStatus(status), data: encryptedData)
                    // Free memory allocated for encrypted data
                    cipherText.destroy()
                })
            }
            else {
                // Public key not found
                dispatch_async(dispatch_get_main_queue(), {
                    completion(error: .NotFound, data: nil)
                })
            }
        })
    }
    
    // Encrypt message (String) with public key
    func encryptMessageWithPublicKey(message: String,
                                     completion: (error: SecureManagerErrors, data: NSData?) -> Void) {
        // Convert message from String into NSData
        guard let messageData = message.dataUsingEncoding(NSUTF8StringEncoding) else {
            // Wrong data format
            completion(error: .BadRequest, data: nil)
            return
        }
        
        // Encrypt NSData
        encryptDataWithPublicKey(messageData, completion: {
            (error, data) in completion(error: error, data: data)
        })
    }
    
    // Decrypt data with private key, result type is NSData?
    func decryptDataWithPrivateKey(encryptedData: NSData,
                                   completion: (error: SecureManagerErrors, data: NSData?) -> Void) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), {
            [unowned self] in
            if let privateKeyRef = self.privateKeyReference() {
                
                // Buffer for decrypted data
                guard let decryptedData = NSMutableData(length: SecKeyGetBlockSize(privateKeyRef)) else {
                    dispatch_async(dispatch_get_main_queue(), {
                        // Can't allocate memory for output data
                        completion(error: .NotAvailable, data: nil)
                    })
                    return
                }
                
                // Pointer to the data to be decrypted
                let encryptedText = UnsafePointer<UInt8>(encryptedData.bytes)
                let encryptedTextLength = encryptedData.length
                
                // Pointer to decrypted data
                let plainText = UnsafeMutablePointer<UInt8>(decryptedData.mutableBytes)
                var plainTextLength = decryptedData.length
                
                let status = SecKeyDecrypt(privateKeyRef,
                                        .PKCS1,
                                        encryptedText,
                                        encryptedTextLength,
                                        plainText,
                                        &plainTextLength)
                
                dispatch_async(dispatch_get_main_queue(), {
                    [unowned self] in
                    // Adjust decrypted data length
                    decryptedData.length = plainTextLength
                    // Decryption result
                    completion(error: self.checkStatus(status), data: decryptedData)
                    // Free memory allocated for decrypted data
                    plainText.destroy()
                })
            }
            else {
                // Private key not found
                dispatch_async(dispatch_get_main_queue(), {
                    completion(error: .NotFound, data: nil)
                })
            }
        })
    }
    
    // Decrypt data with private key, result type is String?
    func decryptMessageWithPrivateKey(encryptedData: NSData,
                                      completion: (error: SecureManagerErrors, message: String?) -> Void) {
        
        decryptDataWithPrivateKey(encryptedData, completion: {
            (decryptionError, data) -> Void in
            
            if .NoError == decryptionError {
                if let decryptedData = data,
                    // Convert NSData into String
                    let string = String(data: decryptedData, encoding: NSUTF8StringEncoding) {
                    // Result
                    completion(error: .NoError, message: string)
                }
                else {
                    // Wrong data format
                    completion(error: .BadRequest, message: nil)
                }
            }
            else {
                // Something is wrong
                completion(error: decryptionError, message: nil)
            }
        })
    }
    
    // Sign data (NSData) with private key
    func signDataWithPrivateKey(data: NSData,
                                completion: (error: SecureManagerErrors, signature: NSData?) -> Void) {
        
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), {
            [unowned self] in
            if let privateKeyRef = self.privateKeyReference() {
                
                // Buffer for signature data
                guard let signatureData = NSMutableData(length: SecKeyGetBlockSize(privateKeyRef)) else {
                    dispatch_async(dispatch_get_main_queue(), {
                        // Can't allocate memory for output data
                        completion(error: .NotAvailable, signature: nil)
                    })
                    return
                }
                
                // Buffer for hash data
                guard let hashData = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH)) else {
                    dispatch_async(dispatch_get_main_queue(), {
                        // Can't allocate memory for output data
                        completion(error: .NotAvailable, signature: nil)
                    })
                    return
                }
                
                // Pointer to the signature data
                let signatureText = UnsafeMutablePointer<UInt8>(signatureData.mutableBytes)
                var signatureTextLength = signatureData.length
                
                // Pointer to hash data
                let hash = UnsafeMutablePointer<UInt8>(hashData.mutableBytes)
                
                // Generate hash
                CC_SHA256(UnsafePointer<Void>(data.bytes), CC_LONG(data.length), hash)
                
                // Sign the hash
                let status = SecKeyRawSign(privateKeyRef,
                                        .PKCS1SHA256,
                                        hash,
                                        hashData.length,
                                        signatureText,
                                        &signatureTextLength)
                
                dispatch_async(dispatch_get_main_queue(), {
                    [unowned self] in
                    // Adjust signature length
                    signatureData.length = signatureTextLength
                    // Result
                    completion(error: self.checkStatus(status), signature: signatureData)
                    // Free memory allocated for signature
                    hash.destroy()
                })
            }
            else {
                dispatch_async(dispatch_get_main_queue(), {
                    // Private key not found
                    completion(error: .NotFound, signature: nil)
                })
            }
        })
    }
    
    // Sign message (String) with private key
    func signMessageWithPrivateKey(message: String,
                                   completion: (error: SecureManagerErrors, signature: NSData?) -> Void) {
        // Convert string into NSData
        guard let messageData = message.dataUsingEncoding(NSUTF8StringEncoding) else {
            // Wrong data format
            completion(error: .BadRequest, signature: nil)
            return
        }
        
        signDataWithPrivateKey(messageData, completion: {
            (error, signature) -> Void in
            completion(error: error, signature: signature)
        })
    }
    
    // Verify signature of the data (NSData)
    func verifyDataWithPublicKey(data: NSData, signature: NSData,
                                 completion: (error: SecureManagerErrors) -> Void) {
        
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), {
            [unowned self] in
            if let publicKeyRef = self.publicKeyReference() {
                
                // Buffer for hash data
                guard let hashData = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH)) else {
                    dispatch_async(dispatch_get_main_queue(), {
                        // Can't allocate memory for output data
                        completion(error: .NotAvailable)
                    })
                    return
                }
                
                // Pointer to hash data
                let hash = UnsafeMutablePointer<UInt8>(hashData.mutableBytes)
                
                // Calculate hash of the input data
                CC_SHA256(UnsafePointer<Void>(data.bytes), CC_LONG(data.length), hash)
                
                // Pointer to the signature data to be verified
                let signatureText = UnsafeMutablePointer<UInt8>(signature.bytes)
                let signatureTextLength = signature.length
                
                let status = SecKeyRawVerify(publicKeyRef,
                                            .PKCS1SHA256,
                                            hash,
                                            Int(CC_SHA256_DIGEST_LENGTH),
                                            signatureText,
                                            signatureTextLength)
                
                dispatch_async(dispatch_get_main_queue(), {
                    [unowned self] in
                    // Result
                    completion(error: self.checkStatus(status))
                    // Free memory allocated for signature
                    hash.destroy()
                })
            }
            else {
                dispatch_async(dispatch_get_main_queue(), {
                    // Public key not found
                    completion(error: .NotFound)
                })
            }
        })
    }
    
    // Verify signature of the message (String)
    func verifyMessageWithPublicKey(message: String, signature: NSData,
                                    completion: (error: SecureManagerErrors) -> Void) {
        
        guard let messageData = message.dataUsingEncoding(NSUTF8StringEncoding) else {
            // Wrong data format
            completion(error: .BadRequest)
            return
        }
        
        verifyDataWithPublicKey(messageData, signature: signature, completion: {
            (error) -> Void in
            completion(error: error)
        })
    }
    
    // Get public key
    func publicKeyData() -> NSData? {
        
        let publicKeyParameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag as String: kSecureManagerApplicationTag,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecReturnData as String: true
        ]
        
        var reference: AnyObject?
        
        // Find a key with required parameters
        let status = SecItemCopyMatching(publicKeyParameters, &reference)
        //print(reference as! NSData)
        return errSecSuccess == status ? reference as! NSData? : nil
    }
    
    // Get private key size (in bytes)
    func privateKeySize() -> Int? {
        guard let privateRef = privateKeyReference() else {
            return nil
        }
        
        return SecKeyGetBlockSize(privateRef)
    }
    
    // Encrypt/decrypt data using AES256 algorithm
    func crypt(data: NSData, withKey key: NSData, encryption: Bool) -> NSData? {
        // Create buffer for output data
        guard let dataOut = NSMutableData(length: data.length + kCCBlockSizeAES128) else {
            return nil
        }
        
        let dataPointer = UnsafePointer<Void>(data.bytes)
        let keyPointer = UnsafePointer<Void>(key.bytes)
        
        let dataOutPointer = UnsafeMutablePointer<Void>(dataOut.mutableBytes)
        var dataOutMoved = 0
        
        let operationType = encryption ? kCCEncrypt : kCCDecrypt
        
        let status = Int(CCCrypt(UInt32(operationType),
                                UInt32(kCCAlgorithmAES),
                                UInt32(kCCOptionPKCS7Padding),
                                keyPointer,
                                kCCKeySizeAES256,
                                nil,
                                dataPointer,
                                data.length,
                                dataOutPointer,
                                dataOut.length,
                                &dataOutMoved))
        
        defer {
            // Release buffer
            dataOutPointer.destroy()
        }
        
        if kCCSuccess == status {
            dataOut.length = dataOutMoved
            //print(dataOut)
            return dataOut
        }
        
        return nil
    }
    
    // Generate random key with length bytes size
    // Return SHA256 hash of the generated key
    func generateKey(withLengthInBytes length: Int) -> NSData? {
        guard let randomData = NSMutableData(capacity: length) else {
            return nil
        }
        
        guard let hashData = NSMutableData(length: length) else {
            return nil
        }
        
        defer {
            // Release buffer
            hash.destroy()
        }
        
        for _ in 0..<length {
            var randomNumber = UInt8(arc4random_uniform(UInt32(UInt8.max)))
            randomData.appendData(NSData(bytes: &randomNumber, length: 1))
        }
        
        // Pointer to hash data
        let hash = UnsafeMutablePointer<UInt8>(hashData.mutableBytes)
        
        // Calculate hash of the input data
        CC_SHA256(UnsafePointer<Void>(randomData.bytes),
                  CC_LONG(CC_SHA256_DIGEST_LENGTH),
                  hash)
        
        return hashData
    }
    
    // Generate random NSData with specific length (in bytes)
    func generateRandomData(withLengthInBytes length: Int) -> NSData? {
        guard let randomData = NSMutableData(capacity: length) else {
            return nil
        }
        
        for _ in 0..<length {
            var randomNumber = UInt8(arc4random_uniform(UInt32(UInt8.max)))
            randomData.appendData(NSData(bytes: &randomNumber, length: 1))
        }
        
        return randomData
    }
    
    // Save password into Keychain
    func savePassword(password: String) -> Bool {
        
        let passwordParameters: [String: AnyObject] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: kSecureManagerApplicationTag
        ]
        //SecItemDelete(passwordParameters)
        var status = SecItemCopyMatching(passwordParameters, nil)
        
        if errSecItemNotFound == status {
            status = SecItemAdd(passwordParameters, nil)
            //errSecSuccess == status ? print("Add success") : print("Add error")
            return errSecSuccess == status
        }
        
        if errSecSuccess == status {
            let status = SecItemUpdate(passwordParameters,
                                       [kSecValueData as String: password.dataUsingEncoding(NSUTF8StringEncoding)!])
            //errSecSuccess == status ? print("Update success") : print("Update error")
            return errSecSuccess == status
        }
        return false
    }
    
    // Read password from Keychain
    func readPassword() -> String? {
        
        let passwordParameters = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: kSecureManagerApplicationTag,
            kSecReturnData as String: kCFBooleanTrue
        ]
        
        var reference: AnyObject?
        let status = SecItemCopyMatching(passwordParameters, &reference)
        
        if errSecSuccess == status {
            guard let data = reference as? NSData else {
                return nil
            }
            
            return String(data: data, encoding: NSUTF8StringEncoding)
        }
        return nil
    }
    
    // MARK: - Private methods
    
    // Get a reference to the public key
    private func publicKeyReference() -> SecKeyRef? {
        
        let publicKeyParameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag as String: kSecureManagerMyTestApplicationTag,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecReturnRef as String: true
        ]
        
        var reference: AnyObject?
        // Find a key with required parameters
        let status = SecItemCopyMatching(publicKeyParameters, &reference)
        print(reference as! SecKeyRef)
        return errSecSuccess == status ? reference as! SecKeyRef? : nil
    }
    
    // Get a reference to the private key
    private func privateKeyReference() -> SecKeyRef? {
        
        let privateKeyParameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag as String: kSecureManagerApplicationTag,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecReturnRef as String: true
        ]
        
        var reference: AnyObject?
        // Find a key with required parameters
        let status = SecItemCopyMatching(privateKeyParameters, &reference)
        return errSecSuccess == status ? reference as! SecKeyRef? : nil
    }
    
    // Convert OSStatus into SecureManagerErrors
    private func checkStatus(status: OSStatus) -> SecureManagerErrors {
        
        switch status {
        case errSecSuccess: return .NoError
        case errSecUnimplemented: return .NotImplemented
        case errSecBadReq: return .BadRequest
        case errSecNotAvailable: return .NotAvailable
        case errSecDuplicateItem: return .DuplicatedItem
        case errSecItemNotFound: return .NotFound
        case errSecAuthFailed: return .AuthFailed
        default: return .UnknownError
        }
    }
}
