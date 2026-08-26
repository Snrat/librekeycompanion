package com.token2.lkcompanion.token2ui

import com.token2.lkcompanion.token2.Token2Client
import com.token2.lkcompanion.token2.Token2Exception
import com.token2.lkcompanion.transport.SmartCardTransport

/**
 * Arm/tap bridge for the OTP-PIN (privacy-protection) commands. These run ONLY
 * over the CCID/NFC transport (the OTP applet answers them with 6A86 over
 * USB-HID), so callers must hand [executeOn] a CCID/NFC-backed client.
 */
class Token2PinRepository {

    sealed class PendingOp {
        object Status : PendingOp()
        data class SetPin(val pin: String) : PendingOp()
        data class VerifyPin(val pin: String) : PendingOp()
        data class ChangePin(val current: String, val new: String) : PendingOp()
        data class RemovePin(val current: String) : PendingOp()
    }

    sealed class OpResult {
        data class Status(val flag: Token2Client.PinFlag) : OpResult()
        data class Success(val message: String) : OpResult()
        /** Wrong PIN or window not open; retriesLeft is the fresh count if known. */
        data class WrongPin(val retriesLeft: Int?) : OpResult()
        /** PIN locked out — erase-all is the only recovery. */
        object Blocked : OpResult()
        /** Firmware lacks the feature (pre-R3.4), or a PIN command failed. */
        data class Unsupported(val detail: String) : OpResult()
        /** Command run over a transport that can't carry PIN commands. */
        object WrongTransport : OpResult()
        data class Failure(val message: String) : OpResult()
    }

    @Volatile var pending: PendingOp = PendingOp.Status
        private set

    fun arm(op: PendingOp) { pending = op }

    /** Run the armed op against a CCID/NFC-backed client. */
    fun executeOn(client: Token2Client): OpResult {
        return try {
            when (val op = pending) {
                is PendingOp.Status -> OpResult.Status(client.pinStatus())
                is PendingOp.SetPin -> {
                    client.setOtpPin(op.pin.toByteArray(Charsets.UTF_8))
                    OpResult.Success("OTP PIN set.")
                }
                is PendingOp.VerifyPin -> {
                    client.verifyOtpPin(op.pin.toByteArray(Charsets.UTF_8))
                    OpResult.Success("PIN verified — codes unlocked.")
                }
                is PendingOp.ChangePin -> {
                    client.changeOtpPin(
                        op.current.toByteArray(Charsets.UTF_8),
                        op.new.toByteArray(Charsets.UTF_8),
                    )
                    OpResult.Success("OTP PIN changed.")
                }
                is PendingOp.RemovePin -> {
                    client.removeOtpPin(op.current.toByteArray(Charsets.UTF_8))
                    OpResult.Success("OTP PIN removed.")
                }
            }
        } catch (e: Token2Exception.PinNotVerified) {
            // Try to report retries-left by re-reading status (best effort).
            val retries = try { client.pinStatus().retriesLeft } catch (_: Exception) { null }
            OpResult.WrongPin(retries)
        } catch (e: Token2Exception.PinBlocked) {
            OpResult.Blocked
        } catch (e: Token2Exception.PinUnsupported) {
            OpResult.Unsupported(e.message ?: "SW=${"%04X".format(e.sw)}")
        } catch (e: Token2Exception.PinTransportUnavailable) {
            OpResult.WrongTransport
        } catch (e: Token2Exception.PinWrongState) {
            OpResult.Failure("Command not allowed in the current PIN state.")
        } catch (e: Exception) {
            OpResult.Failure(e.message ?: e.javaClass.simpleName)
        }
    }
}
