package com.token2.lkcompanion.token2ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.token2.lkcompanion.R
import com.token2.lkcompanion.token2.Token2Codec

/**
 * Renders Token2 on-device OTP entries. TOTP codes the device returned are shown
 * with a per-period countdown; HOTP / button-required entries show a placeholder
 * (their code is only available via an explicit read + button touch).
 */
class Token2EntryAdapter(
    private val onDelete: (Token2Codec.Entry) -> Unit,
    private val onCopy: (Token2Codec.Entry) -> Unit,
) : RecyclerView.Adapter<Token2EntryAdapter.VH>() {

    private var entries: List<Token2Codec.Entry> = emptyList()
    private var unixSeconds: Long = System.currentTimeMillis() / 1000
    private var generatedAtSeconds: Long = unixSeconds

    fun submit(list: List<Token2Codec.Entry>, challengeUnixSeconds: Long? = null) {
        entries = list
        unixSeconds = System.currentTimeMillis() / 1000
        generatedAtSeconds = challengeUnixSeconds ?:
            token2ChallengeTime(list, System.currentTimeMillis() / 1000)
        notifyDataSetChanged()
    }

    /** Called by a 1s ticker so the countdown bar animates between taps. */
    fun tick(nowUnixSeconds: Long) {
        unixSeconds = nowUnixSeconds
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_otp_entry, parent, false)
        return VH(v)
    }

    override fun getItemCount() = entries.size

    override fun onBindViewHolder(holder: VH, position: Int) {
        val e = entries[position]
        holder.title.text = if (e.appName.isBlank()) e.accountName else e.appName
        holder.subtitle.text = e.accountName
        val codeIsCurrent = token2CodeIsCurrent(e, generatedAtSeconds, unixSeconds)
        when {
            codeIsCurrent -> {
                holder.code.text = spaceCode(checkNotNull(e.otpCode))
                val secondsLeft = com.token2.lkcompanion.oath.OathCore
                    .secondsRemaining(unixSeconds, e.timestep)
                holder.meta.text = "TOTP • ${e.timestep}s • ${secondsLeft}s left"
            }
            e.otpCode != null -> {
                holder.code.text = "— — — — — —"
                holder.meta.text = "Expired • refresh to update"
            }
            !e.isTotp -> {
                holder.code.text = "— — — — — —"
                holder.meta.text = "HOTP • read with button touch"
            }
            else -> {
                holder.code.text = "— — — — — —"
                holder.meta.text = "button required"
            }
        }
        holder.delete.setOnClickListener { onDelete(e) }
        // Copy is only meaningful when we actually have a code to copy.
        holder.copy.visibility = if (codeIsCurrent) View.VISIBLE else View.GONE
        holder.copy.setOnClickListener { onCopy(e) }
    }

    private fun spaceCode(code: String): String =
        if (code.length == 6) "${code.substring(0, 3)} ${code.substring(3)}"
        else if (code.length == 8) "${code.substring(0, 4)} ${code.substring(4)}"
        else code

    class VH(v: View) : RecyclerView.ViewHolder(v) {
        val title: TextView = v.findViewById(R.id.entryTitle)
        val subtitle: TextView = v.findViewById(R.id.entrySubtitle)
        val code: TextView = v.findViewById(R.id.entryCode)
        val meta: TextView = v.findViewById(R.id.entryMeta)
        val copy: ImageButton = v.findViewById(R.id.entryCopy)
        val delete: ImageButton = v.findViewById(R.id.entryDelete)
    }
}

internal fun token2ChallengeTime(
    entries: List<Token2Codec.Entry>,
    fallbackUnixSeconds: Long,
): Long = (entries as? Token2EntrySnapshot)?.challengeUnixSeconds ?: fallbackUnixSeconds

internal fun token2CodeIsCurrent(
    entry: Token2Codec.Entry,
    generatedAtUnixSeconds: Long,
    nowUnixSeconds: Long,
): Boolean = entry.otpCode != null &&
    entry.isTotp && entry.timestep > 0 &&
    generatedAtUnixSeconds / entry.timestep == nowUnixSeconds / entry.timestep
