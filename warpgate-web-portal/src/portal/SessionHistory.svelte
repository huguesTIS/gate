<script lang="ts">
    import { getMySessions, type SessionHistoryEntry } from './lib/api'

    let entries: SessionHistoryEntry[] = $state([])
    let loading = $state(true)
    let error: string | null = $state(null)

    async function load() {
        loading = true
        error = null
        try {
            entries = await getMySessions()
        } catch (e) {
            error = e instanceof Error ? e.message : 'Failed to load session history'
        } finally {
            loading = false
        }
    }
    load()

    function formatDuration(started: string, ended?: string): string {
        const start = new Date(started).getTime()
        const end = ended ? new Date(ended).getTime() : Date.now()
        const totalSeconds = Math.max(0, Math.round((end - start) / 1000))
        const hours = Math.floor(totalSeconds / 3600)
        const minutes = Math.floor((totalSeconds % 3600) / 60)
        if (hours > 0) {
            return `${hours}h ${minutes}m`
        }
        return `${minutes}m`
    }

    function formatWhen(started: string): string {
        return new Date(started).toLocaleString()
    }
</script>

<div class="history">
    {#if loading}
        <div class="hint">Loading...</div>
    {:else if error}
        <div class="hint error">{error}</div>
    {:else if entries.length === 0}
        <div class="hint">No past sessions</div>
    {:else}
        {#each entries as entry (entry.id)}
            <div class="entry">
                <div class="entry-main">
                    <span class="target-name">{entry.target_name ?? 'Unknown target'}</span>
                    <span class="protocol-badge">{entry.protocol}</span>
                    {#if entry.has_recording}
                        <span class="recording-badge" title="Recorded">⏺</span>
                    {/if}
                </div>
                <div class="entry-meta">
                    <span>{formatWhen(entry.started)}</span>
                    <span>·</span>
                    <span>{entry.ended ? formatDuration(entry.started, entry.ended) : 'ongoing'}</span>
                </div>
            </div>
        {/each}
    {/if}
</div>

<style>
    .history {
        padding: 4px 0;
    }

    .hint {
        padding: 16px;
        color: #6b7280;
        font-size: 13px;
    }

    .hint.error {
        color: #f87171;
    }

    .entry {
        padding: 8px 14px;
        border-bottom: 1px solid #1f2433;
    }

    .entry-main {
        display: flex;
        align-items: center;
        gap: 6px;
        color: #dde3f0;
        font-size: 13px;
    }

    .target-name {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .protocol-badge {
        flex-shrink: 0;
        font-size: 10px;
        padding: 1px 6px;
        border-radius: 4px;
        background: #2e3446;
        color: #9aa4c0;
        text-transform: uppercase;
    }

    .recording-badge {
        flex-shrink: 0;
        color: #f87171;
        font-size: 10px;
    }

    .entry-meta {
        display: flex;
        gap: 6px;
        margin-top: 2px;
        color: #6b7280;
        font-size: 11px;
    }
</style>
