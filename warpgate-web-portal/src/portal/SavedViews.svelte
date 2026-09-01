<script lang="ts">
    import { createSavedView, deleteSavedView, duplicateSavedView, getSavedViews, type SavedView } from './lib/api'

    interface Props {
        currentSearch: string
        activeViewId?: string
        onApply: (view: SavedView) => void
    }
    let { currentSearch, activeViewId, onApply }: Props = $props()

    let views: SavedView[] = $state([])
    let creating = $state(false)
    let newName = $state('')

    async function load() {
        try {
            views = await getSavedViews()
        } catch {
            // Non-critical: the sidebar still works without saved views.
        }
    }
    load()

    function startCreate() {
        creating = true
        newName = ''
    }

    async function confirmCreate() {
        const name = newName.trim()
        if (!name) {
            creating = false
            return
        }
        const created = await createSavedView({
            name,
            filter_json: currentSearch ? { search: currentSearch } : null,
            target_ids: [],
        })
        views = [...views, created]
        creating = false
    }

    async function remove(view: SavedView, event: MouseEvent) {
        event.stopPropagation()
        await deleteSavedView(view.id)
        views = views.filter(v => v.id !== view.id)
    }

    async function duplicate(view: SavedView, event: MouseEvent) {
        event.stopPropagation()
        const copy = await duplicateSavedView(view.id)
        views = [...views, copy]
    }
</script>

<div class="saved-views">
    {#each views as view (view.id)}
        <button
            type="button"
            class="chip"
            class:active={view.id === activeViewId}
            class:shared={!view.owned}
            title={view.owned ? undefined : 'Shared with you — read-only'}
            onclick={() => onApply(view)}
        >
            <span class="chip-name">{view.name}</span>
            {#if view.owned}
                <span class="chip-remove" onclick={e => remove(view, e)} role="presentation">×</span>
            {:else}
                <span class="chip-duplicate" onclick={e => duplicate(view, e)} role="presentation">⎘</span>
            {/if}
        </button>
    {/each}

    {#if creating}
        <div class="chip creating">
            <input
                type="text"
                placeholder="View name"
                bind:value={newName}
                onkeydown={e => {
                    if (e.key === 'Enter') confirmCreate()
                    if (e.key === 'Escape') creating = false
                }}
                onblur={confirmCreate}
            />
        </div>
    {:else}
        <button type="button" class="chip add" onclick={startCreate} title="Save current search as a view">
            + Save view
        </button>
    {/if}
</div>

<style>
    .saved-views {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        padding: 0 12px 10px;
    }

    .chip {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 3px 8px;
        border-radius: 999px;
        border: 1px solid #2e3446;
        background: #1f2433;
        color: #9aa4c0;
        font-size: 11px;
        cursor: pointer;
    }

    .chip.active {
        border-color: #5b7cfa;
        color: #dde3f0;
    }

    .chip.add {
        color: #6b7280;
        border-style: dashed;
    }

    .chip.add:hover {
        color: #9aa4c0;
    }

    .chip.shared {
        border-style: dotted;
    }

    .chip-remove {
        color: #6b7280;
    }

    .chip-remove:hover {
        color: #f87171;
    }

    .chip-duplicate {
        color: #6b7280;
    }

    .chip-duplicate:hover {
        color: #5b7cfa;
    }

    .chip.creating input {
        width: 100px;
        border: none;
        background: transparent;
        color: #dde3f0;
        font-size: 11px;
        outline: none;
    }
</style>
