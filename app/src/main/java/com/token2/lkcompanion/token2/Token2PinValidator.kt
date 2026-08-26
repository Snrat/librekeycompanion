package com.token2.lkcompanion.token2

/**
 * Client-side OTP-PIN policy, mirroring the reference `validate_otp_pin`. The
 * device enforces its own policy too, but validating here gives the user a clear
 * message before a wrong-format PIN is ever sent.
 */
object Token2PinValidator {

    /** Returns null if the PIN is acceptable, else a human-readable reason. */
    fun validate(pin: String): String? {
        val bytes = pin.toByteArray(Charsets.UTF_8)
        if (bytes.isEmpty()) return "PIN must not be empty"
        if (bytes.size > 255) return "PIN is too long"

        val allDigits = pin.all { it in '0'..'9' }
        return if (allDigits) validateNumeric(pin) else validateAlphanumeric(pin)
    }

    private fun validateNumeric(pin: String): String? {
        if (pin.length < 6) return "Numeric PIN must be at least 6 digits"
        if (pin.all { it == pin[0] }) return "Numeric PIN must not be all the same digit"
        val asc = pin.zipWithNext().all { (a, b) -> b.code == a.code + 1 }
        val desc = pin.zipWithNext().all { (a, b) -> a.code == b.code + 1 }
        if (asc || desc) return "Numeric PIN must not be a simple ascending/descending sequence"
        if (pin == pin.reversed()) return "Numeric PIN must not be a palindrome"
        for (d in '0'..'9') {
            if (pin.count { it == d } > 3) return "Numeric PIN repeats a single digit too many times"
        }
        return null
    }

    private fun validateAlphanumeric(pin: String): String? {
        if (pin.length < 10) return "Alphanumeric PIN must be at least 10 characters"
        var classes = 0
        if (pin.any { it in 'A'..'Z' }) classes++
        if (pin.any { it in 'a'..'z' }) classes++
        if (pin.any { it in '0'..'9' }) classes++
        if (pin.any { !it.isLetterOrDigit() }) classes++
        if (classes < 2) return "Alphanumeric PIN must mix at least two character types"
        return null
    }
}
