package com.token2.lkcompanion.oath

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Locks the YKOATH password path to published vectors: RFC 6070 for PBKDF2 and
 * RFC 2202 for the HMAC-SHA1 used by VALIDATE. A key derived even one byte
 * differently is rejected by the applet with no diagnostic beyond SW 6982, so
 * the derivation has to be pinned rather than eyeballed.
 */
class OathPasswordTest {

    private fun hex(s: String) = OathPassword.fromHex(s.replace(" ", "").uppercase())

    @Test fun rfc6070_pbkdf2_hmacSha1_vectors() {
        assertArrayEquals(
            hex("0c60c80f961f0e71f3a9b524af6012062fe037a6"),
            OathPassword.pbkdf2HmacSha1("password".toByteArray(), "salt".toByteArray(), 1, 20),
        )
        assertArrayEquals(
            hex("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
            OathPassword.pbkdf2HmacSha1("password".toByteArray(), "salt".toByteArray(), 2, 20),
        )
        // The iteration count the OATH applet uses.
        assertArrayEquals(
            hex("4b007901b765489abead49d926f721d065a429c1"),
            OathPassword.pbkdf2HmacSha1("password".toByteArray(), "salt".toByteArray(), 4096, 20),
        )
        // Multi-block output: exercises the block counter, unlike the 16-byte case.
        assertArrayEquals(
            hex("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"),
            OathPassword.pbkdf2HmacSha1(
                "passwordPASSWORDpassword".toByteArray(),
                "saltSALTsaltSALTsaltSALTsaltSALTsalt".toByteArray(),
                4096,
                25,
            ),
        )
    }

    @Test fun accessKey_is_16_bytes_from_utf8_password_and_deviceId_salt() {
        val deviceId = hex("0102030405060708")
        val key = OathPassword.deriveAccessKey("password", deviceId)
        assertEquals(OathPassword.KEY_LENGTH, key.size)
        assertArrayEquals(
            OathPassword.pbkdf2HmacSha1("password".toByteArray(Charsets.UTF_8), deviceId, 1000, 16),
            key,
        )
    }

    /**
     * The password is hashed as UTF-8, not as 8-bit-truncated chars. Android's
     * SecretKeyFactory has historically done the latter; this asserts we do not.
     */
    @Test fun nonAscii_password_is_encoded_as_utf8() {
        val deviceId = hex("0102030405060708")
        val password = "pässwörd"
        assertArrayEquals(
            OathPassword.pbkdf2HmacSha1(
                password.toByteArray(Charsets.UTF_8), deviceId, 1000, 16),
            OathPassword.deriveAccessKey(password, deviceId),
        )
        assertFalse(
            OathPassword.constantTimeEquals(
                OathPassword.deriveAccessKey(password, deviceId),
                OathPassword.pbkdf2HmacSha1(
                    password.toByteArray(Charsets.ISO_8859_1), deviceId, 1000, 16),
            )
        )
    }

    @Test fun rfc2202_hmacSha1_vector_for_validate_response() {
        assertArrayEquals(
            hex("b617318655057264e28bc0b6fb378c8ef146be00"),
            OathPassword.hmac(
                OathPassword.ALG_SHA1,
                hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                "Hi There".toByteArray(),
            ),
        )
    }

    @Test fun constantTimeEquals_matches_contentEquals() {
        val a = hex("00112233445566778899aabbccddeeff")
        assertTrue(OathPassword.constantTimeEquals(a, a.copyOf()))
        assertFalse(OathPassword.constantTimeEquals(a, a.copyOf(15)))
        val b = a.copyOf().also { it[15] = (it[15] + 1).toByte() }
        assertFalse(OathPassword.constantTimeEquals(a, b))
    }

    @Test fun hex_round_trips() {
        val bytes = hex("0a1b2c3d4e5f")
        assertEquals("0A1B2C3D4E5F", OathPassword.toHex(bytes))
        assertArrayEquals(bytes, OathPassword.fromHex(OathPassword.toHex(bytes)))
    }
}
