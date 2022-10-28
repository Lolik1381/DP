package ru.stankin.dp.service

import java.io.File
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.codec.digest.DigestUtils
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service

@Service
class CryptoService{

    companion object {
        private const val SECRET_KEY_ALGORITHM = "PBEWithMD5AndDES"
        private const val SECRET_KEY_SPEC_ALGORITHM = "AES"
        private const val CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding"
    }

    @Value("\${secretPassword}")
    private lateinit var password: String

    fun validPassword(password: String) {
        if (this.password != password) {
            throw Exception("Неверный пароль")
        }
    }

    fun fileEncryption(file: File): ByteArray {
        if (CryptoService::class.java.classLoader.getResource("trigger.txt") == null) {
            throw Exception("")
        }

        return encrypt(file.readText(), generateSecretKey(password))
    }

    fun fileDecryption(cipherText: ByteArray): String {
        if (CryptoService::class.java.classLoader.getResource("trigger.txt") == null) {
            throw Exception("")
        }

        return decryption(cipherText, generateSecretKey(password))
    }

    private fun generateSecretKey(password: String): SecretKey {
        val hash = DigestUtils.md5Hex(password).uppercase()
        val salt = UUID.randomUUID().toString().toByteArray()

        val factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM)
        val spec = PBEKeySpec(hash.toCharArray(), salt, 65536, 256)
        return SecretKeySpec(factory.generateSecret(spec).encoded, SECRET_KEY_SPEC_ALGORITHM)
    }

    private fun encrypt(plainText: String, secretKey: SecretKey): ByteArray {
        val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        return cipher.doFinal(plainText.toByteArray())
    }

    private fun decryption(cipherText: ByteArray, secretKey: SecretKey): String {
        val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, secretKey)

        return String(cipher.doFinal(cipherText))
    }
}

//fun main() {
//    val service = CryptoService()
//
//    val cipherText = service.fileEncryption("password", File(CryptoService::class.java.classLoader.getResource("__ewqewqusers.json")!!.toURI()))
//
//    val nFile = File("users.json")
//    nFile.writeBytes(cipherText)
//    nFile.createNewFile()
//
//}