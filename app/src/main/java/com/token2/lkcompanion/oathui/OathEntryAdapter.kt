package com.token2.lkcompanion.oathui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.token2.lkcompanion.R

/**
 * Renders OATH credentials into the shared OTP row layout (item_otp_entry.xml).
 * TOTP rows show a live code with a per-period countdown; non-TOTP rows show a
 * placeholder. Mirrors Token2EntryAdapter so the OTP tab looks identical whether
 * the key uses the Token2 or OATH applet.
 */
class OathEntryAdapter(
    private val onDelete: (OathRepository.Display) -> Unit,
    private val onCopy: (OathRepository.Display) -> Unit,
    private val onCalculate: (OathRepository.Display) -> Unit,
) : RecyclerView.Adapter<OathEntryAdapter.VH>() {

    private var entries: List<OathRepository.Display> = emptyList()
    private var unixSeconds: Long = System.currentTimeMillis() / 1000

    fun submit(list: List<OathRepository.Display>) {
        entries = list
        unixSeconds = System.currentTimeMillis() / 1000
        notifyDataSetChanged()
    }

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
        holder.title.text = if (e.issuer.isBlank()) e.account else e.issuer
        holder.subtitle.text = e.account
        val uiState = oathEntryUiState(e, unixSeconds)
        when {
            uiState.codeIsCurrent -> {
                holder.code.text = spaceCode(requireNotNull(e.code))
                if (e.isTotp) {
                    val secondsLeft = com.token2.lkcompanion.oath.OathCore
                        .secondsRemaining(unixSeconds, e.period)
                    holder.meta.text = "TOTP • ${e.period}s • ${secondsLeft}s left"
                } else {
                    holder.meta.text = "HOTP • tap row to generate next"
                }
            }
            e.code != null -> {
                holder.code.text = "— — — — — —"
                holder.meta.text = if (uiState.calculateOnRowTap) {
                    "TOTP • expired • tap row to refresh"
                } else {
                    "Expired"
                }
            }
            e.touchRequired -> {
                holder.code.text = "— — — — — —"
                holder.meta.text = if (uiState.calculateOnRowTap) {
                    if (e.isTotp) {
                        "TOTP • ${e.period}s • tap row to generate"
                    } else {
                        "HOTP • tap row to generate"
                    }
                } else if (e.isTotp) {
                    "TOTP • ${e.period}s • touch required"
                } else {
                    "HOTP • touch required"
                }
            }
            !e.isTotp -> {
                holder.code.text = "— — — — — —"
                holder.meta.text = "HOTP • select to generate"
            }
            else -> {
                holder.code.text = "— — — — — —"
                holder.meta.text = if (uiState.calculateOnRowTap) {
                    "TOTP • ${e.period}s • tap row to refresh"
                } else {
                    "Code unavailable • refresh"
                }
            }
        }
        holder.delete.setOnClickListener { onDelete(e) }
        holder.copy.visibility = if (uiState.showCopy) View.VISIBLE else View.GONE
        holder.copy.setOnClickListener(if (uiState.showCopy) {
            View.OnClickListener { onCopy(e) }
        } else {
            null
        })
        holder.itemView.isClickable = uiState.calculateOnRowTap
        holder.itemView.setOnClickListener(if (uiState.calculateOnRowTap) {
            View.OnClickListener { onCalculate(e) }
        } else {
            null
        })
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
