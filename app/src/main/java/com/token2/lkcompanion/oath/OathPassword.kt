package com.token2.lkcompanion.oath

import com.token2.lkcompanion.transport.TransportException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * YKOATH password support: the access-key derivation and the HMAC proof used by
 * VALIDATE (INS A3).
 *
 * A password-protected OATH applet answers SELECT normally but returns a
 * challenge (tag 0x74) and rejects every other instruction with SW 6982
 * (security status not satisfied) until VALIDATE succeeds. The access key is
 *
 *   PBKDF2-HMAC-SHA1(UTF-8(password), salt = device id, 1000 iterations, 16 bytes)
 *
 * where the device id is the name TLV (0x71) from the SELECT response.
 *
 * PBKDF2 is implemented here instead of via `SecretKeyFactory` on purpose:
 * Android's "PBKDF2WithHmacSHA1" provider encodes the `char[]` password with an
 * implementation-defined rule (8-bit truncation on some releases), which
 * silently derives a different key for non-ASCII passwords. Encoding the
 * password as UTF-8 ourselves matches yubikey-manager and Yubico Authenticator,
 * i.e. whatever tool actually set the password on the key.
 */
object OathPassword {

    const val ITERATIONS = 1000
    const val KEY_LENGTH = 16

    /** SELECT tag 0x7B values: which HMAC the applet uses for VALIDATE. */
    const val ALG_SHA1 = 0x01
    const val ALG_SHA256 = 0x02
    const val ALG_SHA512 = 0x03

    fun deriveAccessKey(password: String, deviceId: ByteArray): ByteArray {
        val bytes = password.toByteArray(Charsets.UTF_8)
        if (bytes.isEmpty()) throw TransportException("OATH password must not be empty")
        return pbkdf2HmacSha1(bytes, deviceId, ITERATIONS, KEY_LENGTH)
    }

    /** RFC 2898 PBKDF2 with HMAC-SHA1 as the PRF (verified against RFC 6070). */
    fun pbkdf2HmacSha1(
        password: ByteArray,
        salt: ByteArray,
        iterations: Int,
        length: Int,
    ): ByteArray {
        require(password.isNotEmpty()) { "password must not be empty" }
        require(iterations > 0) { "iterations must be positive" }
        require(length > 0) { "length must be positive" }

        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(password, "HmacSHA1"))

        val out = ByteArray(length)
        var written = 0
        var block = 1
        while (written < length) {
            mac.update(salt)
            mac.update(
                byteArrayOf(
                    (block ushr 24).toByte(),
                    (block ushr 16).toByte(),
                    (block ushr 8).toByte(),
                    block.toByte(),
                )
            )
            var u = mac.doFinal()
            val t = u.copyOf()
            for (round in 2..iterations) {
                u = mac.doFinal(u)
                for (i in t.indices) t[i] = (t[i].toInt() xor u[i].toInt()).toByte()
            }
            val take = minOf(t.size, length - written)
            System.arraycopy(t, 0, out, written, take)
            written += take
            block++
        }
        return out
    }

    fun hmac(algorithm: Int, key: ByteArray, data: ByteArray): ByteArray {
        val name = when (algorithm) {
            ALG_SHA256 -> "HmacSHA256"
            ALG_SHA512 -> "HmacSHA512"
            else -> "HmacSHA1"
        }
        val mac = Mac.getInstance(name)
        mac.init(SecretKeySpec(key, name))
        return mac.doFinal(data)
    }

    /** Comparison of authentication tags must not leak position via timing. */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    fun toHex(bytes: ByteArray): String = bytes.joinToString("") { "%02X".format(it) }

    fun fromHex(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "odd-length hex string" }
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}

/**
 * The OATH applet is password protected and no (valid) password is cached, so
 * the operation cannot proceed. Carries the device id, which is the salt the UI
 * needs to derive the access key from a password the user types.
 */
class OathPasswordRequiredException(val deviceId: ByteArray) : TransportException(
    "OATH applet is password protected"
)

/** VALIDATE was attempted and the key rejected the derived access key. */
class OathPasswordIncorrectException(val deviceId: ByteArray) : TransportException(
    "Incorrect OATH password"
)
