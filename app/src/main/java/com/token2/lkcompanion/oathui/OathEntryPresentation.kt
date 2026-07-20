package com.token2.lkcompanion.oathui

internal data class OathEntryUiState(
    val codeIsCurrent: Boolean,
    val showCopy: Boolean,
    val calculateOnRowTap: Boolean,
)

internal fun oathEntryUiState(
    entry: OathRepository.Display,
    nowUnixSeconds: Long,
): OathEntryUiState {
    val codeIsCurrent = entry.code != null && (
        !entry.isTotp ||
            entry.period > 0 && entry.generatedAtSeconds != null &&
            entry.generatedAtSeconds / entry.period == nowUnixSeconds / entry.period
        )
    val calculateOnRowTap = entry.backend == OathRepository.BackendKind.FEITIAN &&
        (!entry.isTotp || !codeIsCurrent)
    return OathEntryUiState(
        codeIsCurrent = codeIsCurrent,
        showCopy = codeIsCurrent,
        calculateOnRowTap = calculateOnRowTap,
    )
}
