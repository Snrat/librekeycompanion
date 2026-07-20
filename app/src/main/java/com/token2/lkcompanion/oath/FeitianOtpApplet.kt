package com.token2.lkcompanion.oath

import com.token2.lkcompanion.transport.Apdu
import com.token2.lkcompanion.transport.ResponseApdu
import com.token2.lkcompanion.transport.SmartCardTransport
import com.token2.lkcompanion.transport.TransportException
import java.io.ByteArrayOutputStream

class FeitianTouchTimeoutException(operation: String) :
    TransportException("Touch timeout while authorizing Feitian $operation. Please try again.")

/** Client for the proprietary OTP applet used by Feitian ePass FIDO keys. */
class FeitianOtpApplet(private val transport: SmartCardTransport) {

    companion object {
        val AID = byteArrayOf(
            0xD1.toByte(), 0x56, 0x00, 0x01, 0x32, 0x83.toByte(), 0x26, 0x01, 0x01
        )

        private const val SLOT_DEFAULT = 0xF0
        private const val INS_DELETE = 0x08
        private const val INS_PUT = 0x09
        private const val INS_LIST = 0x17
        private const val INS_CALCULATE = 0xA2

        private const val TAG_NAME = 0x51
        private const val TAG_NAME_LIST = 0x52
        private const val TAG_KEY = 0x53
        private const val TAG_CHALLENGE = 0x54
        private const val TAG_TOUCH = 0x5C
        private const val TAG_RESPONSE_TRUNCATED = 0x76

        private const val TYPE_HOTP = 0x10
        private const val TYPE_TOTP = 0x20
        private const val ALG_SHA1 = 0x01
        private const val ALG_SHA256 = 0x02

        private fun logicalName(credential: OathCredential): String =
            if (credential.issuer.isNullOrBlank()) credential.account
            else "${credential.issuer}_#_${credential.account}"

        internal fun protocolName(credential: OathCredential): String {
            val name = logicalName(credential)
            return if (credential.type == OathCredential.Type.TOTP) {
                require(credential.period == 30 || credential.period == 60) {
                    "Feitian TOTP period must be 30 or 60"
                }
                "${credential.period}:$name"
            } else {
                name
            }
        }
    }

    data class StoredCredential(
        val name: String,
        /** Exact name returned by LIST; CALCULATE and DELETE must echo it unchanged. */
        val protocolName: String,
        val type: OathCredential.Type,
        val algorithm: OathCore.HashAlgo,
        val period: Int,
    ) {
        val isTotp: Boolean get() = type == OathCredential.Type.TOTP
    }

    fun select() {
        transport.selectApplet(AID)
    }

    fun list(): List<StoredCredential> {
        var apduResponse = transport.transceive(
            Apdu.build(0x00, INS_LIST, 0x00, SLOT_DEFAULT, le = 0x00)
        )
        if (apduResponse.sw == 0x6700) {
            // The current desktop manager uses this four-byte slot-0 fallback
            // for older Feitian firmware that rejects the default-slot form.
            apduResponse = transport.transceive(
                Apdu.build(0x00, INS_LIST, 0x00, 0x00)
            )
        }
        val response = responseData("LIST", apduResponse)
        val result = ArrayList<StoredCredential>()
        var offset = 0
        while (offset < response.size) {
            if (offset + 2 > response.size) {
                throw TransportException("Feitian LIST returned a truncated TLV header")
            }
            val tag = response[offset].toInt() and 0xFF
            val length = response[offset + 1].toInt() and 0xFF
            val valueStart = offset + 2
            val valueEnd = valueStart + length
            if (valueEnd > response.size) {
                throw TransportException("Feitian LIST returned a truncated TLV value")
            }
            if (tag == TAG_NAME_LIST && length >= 2) {
                parseListEntry(response.copyOfRange(valueStart, valueEnd))?.let(result::add)
            }
            offset = valueEnd
        }
        return result
    }

    fun put(credential: OathCredential, requireTouch: Boolean = false) {
        val logicalName = logicalName(credential)
        val protocolName = protocolName(credential).toByteArray(Charsets.UTF_8)
        validateCredential(credential, logicalName, protocolName)
        val algorithm = when (credential.algo) {
            OathCore.HashAlgo.SHA1 -> ALG_SHA1
            OathCore.HashAlgo.SHA256 -> ALG_SHA256
            OathCore.HashAlgo.SHA512 -> error("Feitian OTP does not support SHA-512")
        }
        val type = if (credential.type == OathCredential.Type.TOTP) TYPE_TOTP else TYPE_HOTP
        val key = byteArrayOf(algorithm.toByte(), type.toByte(), credential.digits.toByte()) +
            credential.secret

        val body = ByteArrayOutputStream().apply {
            writeTlv(TAG_KEY, key)
            writeTlv(TAG_NAME, protocolName)
            if (requireTouch) writeTlv(TAG_TOUCH, byteArrayOf(0x01))
        }.toByteArray()

        // Feitian's own client declares the 0x53 value one byte shorter than the
        // serialized algorithm/type/digits/seed value. The token expects this quirk.
        body[1] = (body[1].toInt() - 1).toByte()
        send("PUT", Apdu.build(0x00, INS_PUT, 0x00, SLOT_DEFAULT, body))
    }

    fun delete(protocolName: String) {
        val encodedName = protocolName.toByteArray(Charsets.UTF_8)
        require(encodedName.isNotEmpty()) { "Feitian OTP name must not be empty" }
        val body = ByteArrayOutputStream().apply {
            writeTlv(TAG_NAME, encodedName)
        }.toByteArray()
        send("DELETE", Apdu.build(0x00, INS_DELETE, 0x00, SLOT_DEFAULT, body))
    }

    fun calculate(
        protocolName: String,
        type: OathCredential.Type,
        period: Int,
        unixSeconds: Long,
    ): String {
        val challenge = if (type == OathCredential.Type.TOTP) {
            require(period == 30 || period == 60) { "Feitian TOTP period must be 30 or 60" }
            longToBigEndian(unixSeconds / period)
        } else {
            ByteArray(0)
        }
        val encodedName = protocolName.toByteArray(Charsets.UTF_8)
        require(encodedName.isNotEmpty()) { "Feitian OTP name must not be empty" }
        val body = ByteArrayOutputStream().apply {
            writeTlv(TAG_CHALLENGE, challenge)
            writeTlv(TAG_NAME, encodedName)
        }.toByteArray()
        // Current Feitian SK Manager sends P1=01 for both HOTP and TOTP.
        // Older FT Authenticator builds used 00 for TOTP, which can produce a
        // response that does not match the supplied time-step on newer keys.
        val p1 = 0x01
        val response = send(
            "CALCULATE",
            Apdu.build(0x00, INS_CALCULATE, p1, SLOT_DEFAULT, body)
        )
        return decodeCode(response)
    }

    private fun parseListEntry(value: ByteArray): StoredCredential? {
        val packed = value[0].toInt() and 0xFF
        val type = when (packed and 0xF0) {
            TYPE_HOTP -> OathCredential.Type.HOTP
            TYPE_TOTP -> OathCredential.Type.TOTP
            else -> return null
        }
        val algorithm = when (packed and 0x0F) {
            ALG_SHA1 -> OathCore.HashAlgo.SHA1
            ALG_SHA256 -> OathCore.HashAlgo.SHA256
            else -> return null
        }
        val protocolNameBytes = value.copyOfRange(1, value.size)
        if (protocolNameBytes.isEmpty()) return null
        var nameBytes = protocolNameBytes
        var period = 30
        if (type == OathCredential.Type.TOTP) {
            val prefixedPeriod = if (nameBytes.size >= 3 &&
                nameBytes[2] == ':'.code.toByte()) {
                when {
                    nameBytes[0] == '3'.code.toByte() &&
                        nameBytes[1] == '0'.code.toByte() -> 30
                    nameBytes[0] == '6'.code.toByte() &&
                        nameBytes[1] == '0'.code.toByte() -> 60
                    else -> null
                }
            } else {
                null
            }
            if (prefixedPeriod != null) {
                period = prefixedPeriod
                nameBytes = nameBytes.copyOfRange(3, nameBytes.size)
            }
        }
        if (nameBytes.isEmpty()) return null
        return StoredCredential(
            String(nameBytes, Charsets.UTF_8),
            String(protocolNameBytes, Charsets.UTF_8),
            type,
            algorithm,
            period,
        )
    }

    private fun decodeCode(data: ByteArray): String {
        if (data.size < 7) throw TransportException("Feitian CALCULATE response is too short")
        val tag = data[0].toInt() and 0xFF
        val length = data[1].toInt() and 0xFF
        if (tag != TAG_RESPONSE_TRUNCATED) {
            throw TransportException("Unexpected Feitian CALCULATE tag %02X".format(tag))
        }
        if (length < 5 || data.size < length + 2) {
            throw TransportException("Malformed Feitian CALCULATE response")
        }
        val digits = data[2].toInt() and 0xFF
        if (digits != 6 && digits != 8) {
            throw TransportException("Unsupported Feitian OTP digit count: $digits")
        }
        val binary = ((data[3].toLong() and 0x7F) shl 24) or
            ((data[4].toLong() and 0xFF) shl 16) or
            ((data[5].toLong() and 0xFF) shl 8) or
            (data[6].toLong() and 0xFF)
        var modulus = 1L
        repeat(digits) { modulus *= 10L }
        return (binary % modulus).toString().padStart(digits, '0')
    }

    private fun validateCredential(
        credential: OathCredential,
        logicalName: String,
        encodedProtocolName: ByteArray,
    ) {
        if (credential.type == OathCredential.Type.HOTP) {
            // Libre currently mirrors the vendor clients' zero-counter PUT flow.
            require(credential.counter == 0L) {
                "Libre currently supports only an initial HOTP counter of 0"
            }
        }
        require(logicalName.toByteArray(Charsets.UTF_8).isNotEmpty()) {
            "Feitian OTP name must not be empty"
        }
        require(encodedProtocolName.size <= 64) {
            "Feitian OTP protocol name must be at most 64 UTF-8 bytes"
        }
        require(credential.secret.size in 1..64) { "Feitian OTP secret must be 1..64 bytes" }
        require(credential.digits == 6 || credential.digits == 8) {
            "Feitian OTP supports only 6 or 8 digits"
        }
        require(credential.algo == OathCore.HashAlgo.SHA1 ||
            credential.algo == OathCore.HashAlgo.SHA256) {
            "Feitian OTP supports only SHA-1 and SHA-256"
        }
        if (credential.type == OathCredential.Type.TOTP) {
            require(credential.period == 30 || credential.period == 60) {
                "Feitian TOTP period must be 30 or 60"
            }
        }
    }

    private fun send(operation: String, command: ByteArray): ByteArray {
        return responseData(operation, transport.transceive(command))
    }

    private fun responseData(operation: String, response: ResponseApdu): ByteArray {
        if (!response.isSuccess) {
            val message = when (response.sw) {
                0x6984 -> throw FeitianTouchTimeoutException(operation)
                0x6982 -> "Feitian OTP access code is required and is not supported yet."
                0x6A80 -> "Feitian $operation rejected the command data."
                0x6A84 -> "The Feitian key does not have enough space."
                else -> "Feitian $operation SW=${"%04X".format(response.sw)}"
            }
            throw TransportException(message)
        }
        return response.data
    }

    private fun ByteArrayOutputStream.writeTlv(tag: Int, value: ByteArray) {
        require(value.size < 128) { "Feitian OTP TLV value is too long" }
        write(tag and 0xFF)
        write(value.size)
        write(value)
    }

    private fun longToBigEndian(value: Long): ByteArray {
        val out = ByteArray(8)
        var remaining = value
        for (i in 7 downTo 0) {
            out[i] = (remaining and 0xFF).toByte()
            remaining = remaining ushr 8
        }
        return out
    }
}
