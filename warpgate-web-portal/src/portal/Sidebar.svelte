<script lang="ts">
    import { addFavorite, getFavorites, getTargetLabels, getTargets, removeFavorite, type SavedView, type TargetSnapshot } from './lib/api'
    import SavedViews from './SavedViews.svelte'
    import SessionHistory from './SessionHistory.svelte'

    interface Props {
        activeTargetId?: string
        onSelect: (target: TargetSnapshot) => void
    }
    let { activeTargetId, onSelect }: Props = $props()

    let showHistory = $state(false)

    const FAVORITES_GROUP = ' favorites' // sorts before any real group name

    // One active grouping axis at a time, not a tree: a target legitimately belongs
    // to several of these at once (type, target group, any label), so forcing one
    // into a fixed hierarchy would be arbitrary. See ARCHITECTURE_TECHNIQUE.md §13,
    // "Panneau latéral" — decided, not reopened without cause. `'label:<key>'` is an
    // open-ended axis (any target_labels key, e.g. "site" but not limited to it) —
    // same generalization as the tab "Group by" selector in App.svelte.
    type GroupAxis = 'none' | 'type' | 'target_group' | `label:${string}`
    let groupAxis: GroupAxis = $state('target_group')

    let search = $state('')
    let targets: TargetSnapshot[] = $state([])
    let favoriteIds: Set<string> = $state(new Set())
    let labelsByTarget: Record<string, Record<string, string>> = $state({})
    let availableLabelKeys: string[] = $state([])
    let loading = $state(true)
    let error: string | null = $state(null)
    // A view's manually-pinned targets (`target_ids`) must stay visible even when they
    // don't match the current search text — see ARCHITECTURE_TECHNIQUE.md §13, a saved
    // view combines a filter with a manual selection, either half may be what matters.
    // Filtering client-side (fetch once, no re-fetch per keystroke) is what makes that
    // simple: the manual list and the search text just union over one already-loaded set.
    let activeView: SavedView | undefined = $state<SavedView | undefined>(undefined)

    // SSH, RDP and VNC are wired end-to-end (see ARCHITECTURE_TECHNIQUE.md §13); database
    // targets still reuse the classic gateway app for now.
    function isConnectable(target: TargetSnapshot): boolean {
        return target.kind === 'Ssh' || target.kind === 'Rdp' || target.kind === 'Vnc'
    }

    async function load() {
        loading = true
        error = null
        try {
            targets = await getTargets()
        } catch (e) {
            error = e instanceof Error ? e.message : 'Failed to load targets'
        } finally {
            loading = false
        }
    }

    async function loadFavorites() {
        try {
            favoriteIds = new Set(await getFavorites())
        } catch {
            // Non-critical: favorites just won't be pinned/starred this load.
        }
    }

    async function loadLabels() {
        try {
            const labels = await getTargetLabels()
            const byTarget: Record<string, Record<string, string>> = {}
            const keys = new Set<string>()
            for (const l of labels) {
                ;(byTarget[l.target_id] ??= {})[l.key] = l.value
                keys.add(l.key)
            }
            labelsByTarget = byTarget
            availableLabelKeys = [...keys].sort()
        } catch {
            // Non-critical: the "group by label" axes just won't be offered.
        }
    }

    function onSearchInput() {
        // Editing the search by hand diverges from the applied view's own filter, so
        // its pinned targets stop being force-included — matches SavedViews.svelte's
        // chip losing its "active" highlight for the same reason.
        activeView = undefined
    }

    function applyView(view: SavedView) {
        activeView = view
        search = view.filter_json?.search ?? ''
    }

    async function toggleFavorite(target: TargetSnapshot, event: MouseEvent) {
        event.stopPropagation()
        const isFavorite = favoriteIds.has(target.id)
        // Optimistic update; revert on failure.
        const next = new Set(favoriteIds)
        if (isFavorite) {
            next.delete(target.id)
        } else {
            next.add(target.id)
        }
        favoriteIds = next
        try {
            if (isFavorite) {
                await removeFavorite(target.id)
            } else {
                await addFavorite(target.id)
            }
        } catch {
            await loadFavorites()
        }
    }

    load()
    loadFavorites()
    loadLabels()

    function axisKeyFor(target: TargetSnapshot): string {
        switch (groupAxis) {
            case 'none':
                return ''
            case 'type':
                return target.kind
            case 'target_group':
                return target.group?.name ?? ''
            default: {
                const labelKey = groupAxis.slice('label:'.length)
                return labelsByTarget[target.id]?.[labelKey] ?? ''
            }
        }
    }

    const pinnedIds = $derived(new Set(activeView?.target_ids ?? []))

    const visibleTargets = $derived.by(() => {
        const needle = search.trim().toLowerCase()
        if (!needle) {
            return targets
        }
        return targets.filter(
            t =>
                pinnedIds.has(t.id) ||
                t.name.toLowerCase().includes(needle) ||
                (t.group?.name ?? '').toLowerCase().includes(needle),
        )
    })

    const grouped = $derived.by(() => {
        const groups = new Map<string, TargetSnapshot[]>()
        const favorites = visibleTargets.filter(t => favoriteIds.has(t.id))
        if (favorites.length > 0) {
            groups.set(FAVORITES_GROUP, favorites)
        }
        for (const t of visibleTargets) {
            const key = axisKeyFor(t)
            if (!groups.has(key)) {
                groups.set(key, [])
            }
            groups.get(key)!.push(t)
        }
        return [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))
    })
</script>

<aside class="sidebar">
    <div class="search-box">
        <input
            type="text"
            placeholder="Search connections..."
            bind:value={search}
            oninput={onSearchInput}
        />
    </div>

    <div class="view-tabs">
        <button type="button" class="view-tab" class:active={!showHistory} onclick={() => (showHistory = false)}>
            Connections
        </button>
        <button type="button" class="view-tab" class:active={showHistory} onclick={() => (showHistory = true)}>
            History
        </button>
    </div>

    {#if showHistory}
        <SessionHistory />
    {:else}
        <SavedViews currentSearch={search} activeViewId={activeView?.id} onApply={applyView} />

        <label class="group-by">
            Group by
            <select bind:value={groupAxis}>
                <option value="none">None</option>
                <option value="type">Type</option>
                <option value="target_group">Target group</option>
                {#each availableLabelKeys as key (key)}
                    <option value={`label:${key}`}>{key}</option>
                {/each}
            </select>
        </label>

        <div class="target-list">
        {#if loading}
            <div class="hint">Loading...</div>
        {:else if error}
            <div class="hint error">{error}</div>
        {:else if targets.length === 0}
            <div class="hint">No connections available</div>
        {:else if visibleTargets.length === 0}
            <div class="hint">No results</div>
        {:else}
            {#each grouped as [groupName, items] (groupName)}
                {#if groupName === FAVORITES_GROUP}
                    <div class="group-header">★ Favorites</div>
                {:else if groupName}
                    <div class="group-header">{groupName}</div>
                {/if}
                {#each items as target (target.id)}
                    <!-- biome-ignore lint/a11y/useSemanticElements: nested interactive star-toggle button, same pattern as WebSsh.svelte's tab items -->
                    <div
                        class="target-item"
                        class:active={target.id === activeTargetId}
                        class:disabled={!isConnectable(target)}
                        tabindex="0"
                        role="button"
                        title={isConnectable(target)
                            ? target.description
                            : `${target.kind} not yet supported in this portal`}
                        onclick={() => isConnectable(target) && onSelect(target)}
                        onkeydown={e => {
                            if (e.key === 'Enter' && isConnectable(target)) onSelect(target)
                        }}
                    >
                        <button
                            type="button"
                            class="star-toggle"
                            class:active={favoriteIds.has(target.id)}
                            aria-label={favoriteIds.has(target.id) ? 'Unfavorite' : 'Favorite'}
                            onclick={e => toggleFavorite(target, e)}
                        >
                            {favoriteIds.has(target.id) ? '★' : '☆'}
                        </button>
                        <span class="kind-badge">{target.kind}</span>
                        <span class="name">{target.name}</span>
                        {#if activeView && pinnedIds.has(target.id)}
                            <span class="pin-badge" title="Pinned in this view">📌</span>
                        {/if}
                    </div>
                {/each}
            {/each}
        {/if}
        </div>
    {/if}
</aside>

<style>
    .sidebar {
        width: 280px;
        flex-shrink: 0;
        display: flex;
        flex-direction: column;
        background: #171a24;
        border-right: 1px solid #262b3a;
        height: 100vh;
    }

    .search-box {
        padding: 12px;
        border-bottom: 1px solid #262b3a;
    }

    .search-box input {
        width: 100%;
        box-sizing: border-box;
        padding: 8px 10px;
        border-radius: 6px;
        border: 1px solid #2e3446;
        background: #12141c;
        color: #dde3f0;
        font-size: 13px;
    }

    .search-box input:focus {
        outline: none;
        border-color: #5b7cfa;
    }

    .view-tabs {
        display: flex;
        gap: 2px;
        padding: 8px 12px 0;
    }

    .view-tab {
        flex: 1;
        padding: 6px;
        border: none;
        border-radius: 4px;
        background: transparent;
        color: #6b7280;
        font-size: 11px;
        cursor: pointer;
    }

    .view-tab:hover {
        background: #1f2433;
    }

    .view-tab.active {
        background: #263056;
        color: #dde3f0;
    }

    .group-by {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 0 12px 10px;
        color: #6b7280;
        font-size: 11px;
    }

    .group-by select {
        flex: 1;
        background: #1f2433;
        color: #9aa4c0;
        border: 1px solid #2e3446;
        border-radius: 4px;
        font-size: 11px;
        padding: 3px 4px;
    }

    .target-list {
        flex: 1;
        overflow-y: auto;
        padding: 8px 0;
    }

    .hint {
        padding: 16px;
        color: #6b7280;
        font-size: 13px;
    }

    .hint.error {
        color: #f87171;
    }

    .group-header {
        padding: 10px 14px 4px;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #6b7280;
    }

    .target-item {
        width: 100%;
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 8px 14px;
        border: none;
        background: transparent;
        color: #dde3f0;
        text-align: left;
        cursor: pointer;
        font-size: 13px;
    }

    .target-item:hover:not(.disabled) {
        background: #1f2433;
    }

    .target-item.active {
        background: #263056;
    }

    .target-item.disabled {
        color: #4b5163;
        cursor: not-allowed;
    }

    .star-toggle {
        flex-shrink: 0;
        width: 20px;
        border: none;
        background: transparent;
        color: #4b5163;
        cursor: pointer;
        font-size: 14px;
        line-height: 1;
        padding: 0;
    }

    .star-toggle.active {
        color: #f5c542;
    }

    .star-toggle:hover {
        color: #f5c542;
    }

    .kind-badge {
        font-size: 10px;
        padding: 1px 6px;
        border-radius: 4px;
        background: #2e3446;
        color: #9aa4c0;
        text-transform: uppercase;
        flex-shrink: 0;
    }

    .name {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .pin-badge {
        flex-shrink: 0;
        font-size: 11px;
    }
</style>
