//
//  AESWrapper.swift
//  EncryptDecrypt
//
//  Created by Shivang Garg on 21/06/18.
//

import Foundation
import CryptoSwift

extension String {
    
    // MARK: - Properties
    private static var _initialVector = ""
    public static var aesInitialVector: String {
        get {
            return String._initialVector
        }
        set(newValue) {
            String._initialVector = newValue
        }
    }
    
    // MARK: - AES Encryption Decryption Helper methods
    // MARK:  Public Encryption AES 128 bit Helpers
    public func encryptAES128(usingKey key:String) -> String {
        
        let aesKey: [UInt8] = Array(key.utf8) as [UInt8]
        assert(aesKey.count < 16, "Key provided is not strong enough for AES 128 bit encryption")
        return aesEncrypt(usingKey: key)
    }
    
    
    public func decryptAES128(usingKey key:String) -> String {

        //Strong key determination
        let aesKey: [UInt8] = Array(key.utf8) as [UInt8]
        assert(aesKey.count < 16, "Key provided is not strong enough for AES 128 bit encryption")
        return aesDecrypt(usingKey: key)
        
    }
    
    // MARK:  Public Encryption AES 192 bit Helpers
    public func encryptAES192(usingKey key: String) -> String {
        
        let aesKey: [UInt8] = Array(key.utf8) as [UInt8]
        assert(aesKey.count < 24, "Key provided is not strong enough for AES 192 bit encryption")
        return aesEncrypt(usingKey: key)
    }
    
    public func decryptAES192(usingKey key:String) -> String {
        
        //Strong key determination
        let aesKey: [UInt8] = Array(key.utf8) as [UInt8]
        assert(aesKey.count < 24, "Key provided is not strong enough for AES 192 bit encryption")
        return aesDecrypt(usingKey: key)
        
    }
    
    // MARK:  Public Encryption AES 256 bit Helpers
    public func encryptAES256(usingKey key: String) -> String {
        
        let aesKey: [UInt8] = Array(key.utf8) as [UInt8]
        assert(aesKey.count < 32, "Key provided is not strong enough for AES 192 bit encryption")
        return aesEncrypt(usingKey: key)
    }
    
    public func decryptAES256(usingKey key:String) -> String {
        
        //Strong key determination
        let aesKey: [UInt8] = Array(key.utf8) as [UInt8]
        assert(aesKey.count < 32, "Key provided is not strong enough for AES 192 bit encryption")
        return aesDecrypt(usingKey: key)
        
    }
    
    // MARK:  Private AES helper methods
    fileprivate func aesEncrypt(usingKey key: String) -> String {
        do {
            let aes = try AES(key: Array(key.utf8) as [UInt8], blockMode: CBC(iv: Array(String.aesInitialVector.utf8)), padding: .pkcs5) // aes128
            let ciphertext = try aes.encrypt(Array(self.utf8))
            return ciphertext.toHexString()
        } catch {
            NSLog("Error while encrypting string = \(error.localizedDescription)")
            return ""
        }
    }
    
    fileprivate func aesDecrypt(usingKey key: String) -> String {
        
        //Converting inputed hex string to Array<UInt8>
        let cipherText = Array<UInt8>.init(hex: self)
        
        do {
            let aes = try AES(key: Array(key.utf8) as [UInt8], blockMode: CBC(iv: Array(String.aesInitialVector.utf8)), padding: .pkcs5) // aes128
            let decrypted = try aes.decrypt(cipherText)
            return String(data: Data(decrypted), encoding: .utf8) ?? ""
        } catch {
            NSLog("Error while decrypting string = \(error.localizedDescription)")
            return ""
        }
    }

    // MARK: - RSA Encryptio Decryption Helper methods
    
    
    
}
