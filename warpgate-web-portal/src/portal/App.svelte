<script lang="ts">
    import { getInfo, getTargetLabels, type TargetSnapshot } from './lib/api'
    import Desktop from './Desktop.svelte'
    import Session from './Session.svelte'
    import Sidebar from './Sidebar.svelte'

    let checking = $state(true)
    let authenticated = $state(false)

    async function checkAuth() {
        try {
            const info = await getInfo()
            authenticated = !!info.username
        } catch {
            authenticated = false
        } finally {
            checking = false
            if (!authenticated) {
                const next = encodeURIComponent(location.href)
                location.assign(`/@warpgate/login?next=${next}`)
            }
        }
    }

    checkAuth()

    // Phase 2 (ARCHITECTURE_TECHNIQUE.md §13): root-level tabs are either a single
    // target or a group of targets sharing the same value for a chosen
    // `target_labels` key (e.g. group by "site" — the axis is user-selectable, not
    // hardcoded to "site" specifically; "site" is just a label like any other, see
    // §13 "Panneau latéral"). Sessions stay mounted whenever their tab isn't the
    // visible one — only hidden via CSS — so switching tabs never drops a
    // connection; only an explicit close does.
    interface TabGroup {
        id: string
        name: string
    }
    interface OpenTarget {
        target: TargetSnapshot
        groupId: string | null // null = a standalone root-level tab
    }

    let groups: TabGroup[] = $state([])
    let openTargets: OpenTarget[] = $state([])
    // Root tab order: a group's id, or a standalone target's id.
    let rootOrder: string[] = $state([])
    let activeRootId: string | undefined = $state(undefined)
    let activeChildByGroup: Record<string, string> = $state({})

    let labelsByTarget: Record<string, Record<string, string>> = $state({})
    let availableLabelKeys: string[] = $state([])
    let groupByLabelKey: string = $state('')

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
            // Non-critical: tabs just won't auto-group without label data.
        }
    }
    loadLabels()

    function activeGroup(): TabGroup | undefined {
        return groups.find(g => g.id === activeRootId)
    }

    // Opening a target: if it's already open somewhere, just navigate to it.
    // Otherwise, if a grouping axis is selected and this target carries that
    // label, it nests inside the (possibly newly-created) tab group for that
    // label's value; targets without the label always open standalone.
    function selectTarget(target: TargetSnapshot) {
        const existing = openTargets.find(t => t.target.id === target.id)
        if (existing) {
            if (existing.groupId) {
                activeRootId = existing.groupId
                activeChildByGroup = { ...activeChildByGroup, [existing.groupId]: target.id }
            } else {
                activeRootId = target.id
            }
            return
        }

        const labelValue = groupByLabelKey ? labelsByTarget[target.id]?.[groupByLabelKey] : undefined
        if (labelValue) {
            const groupId = `label:${groupByLabelKey}:${labelValue}`
            if (!groups.some(g => g.id === groupId)) {
                groups = [...groups, { id: groupId, name: labelValue }]
                rootOrder = [...rootOrder, groupId]
            }
            openTargets = [...openTargets, { target, groupId }]
            activeChildByGroup = { ...activeChildByGroup, [groupId]: target.id }
            activeRootId = groupId
        } else {
            openTargets = [...openTargets, { target, groupId: null }]
            rootOrder = [...rootOrder, target.id]
            activeRootId = target.id
        }
    }

    function activateRoot(id: string) {
        activeRootId = id
    }

    function activateChild(groupId: string, targetId: string) {
        activeRootId = groupId
        activeChildByGroup = { ...activeChildByGroup, [groupId]: targetId }
    }

    function fallbackRoot(closingId: string): string | undefined {
        const closingIndex = rootOrder.indexOf(closingId)
        const remaining = rootOrder.filter(id => id !== closingId)
        return remaining[closingIndex] ?? remaining[closingIndex - 1]
    }

    function closeStandaloneTab(targetId: string, event: MouseEvent) {
        event.stopPropagation()
        openTargets = openTargets.filter(t => t.target.id !== targetId)
        const wasActive = activeRootId === targetId
        rootOrder = rootOrder.filter(id => id !== targetId)
        if (wasActive) {
            activeRootId = fallbackRoot(targetId)
        }
    }

    function closeGroup(groupId: string, event: MouseEvent) {
        event.stopPropagation()
        openTargets = openTargets.filter(t => t.groupId !== groupId)
        groups = groups.filter(g => g.id !== groupId)
        const wasActive = activeRootId === groupId
        rootOrder = rootOrder.filter(id => id !== groupId)
        const { [groupId]: _removed, ...rest } = activeChildByGroup
        activeChildByGroup = rest
        if (wasActive) {
            activeRootId = fallbackRoot(groupId)
        }
    }

    function closeChildTab(groupId: string, targetId: string, event: MouseEvent) {
        event.stopPropagation()
        openTargets = openTargets.filter(
            t => !(t.groupId === groupId && t.target.id === targetId),
        )
        const remainingChildren = openTargets.filter(t => t.groupId === groupId)
        if (remainingChildren.length === 0) {
            // An empty group is just clutter — close it too.
            closeGroup(groupId, event)
            return
        }
        const fallbackChild = remainingChildren[remainingChildren.length - 1]
        if (activeChildByGroup[groupId] === targetId && fallbackChild) {
            activeChildByGroup = {
                ...activeChildByGroup,
                [groupId]: fallbackChild.target.id,
            }
        }
    }

    function isVisible(ot: OpenTarget): boolean {
        if (ot.groupId === null) return ot.target.id === activeRootId
        return activeRootId === ot.groupId && activeChildByGroup[ot.groupId] === ot.target.id
    }
</script>

{#if checking}
    <div class="loading">Loading...</div>
{:else if authenticated}
    <div class="app">
        <Sidebar activeTargetId={activeChildByGroup[activeRootId ?? ''] ?? activeRootId} onSelect={selectTarget} />
        <main>
            {#if rootOrder.length > 0}
                <div class="tab-bar">
                    {#each rootOrder as id (id)}
                        {@const group = groups.find(g => g.id === id)}
                        {@const standalone = openTargets.find(t => t.groupId === null && t.target.id === id)}
                        {#if group}
                            <div
                                class="tab group-tab"
                                class:active={id === activeRootId}
                                tabindex="0"
                                role="button"
                                onclick={() => activateRoot(id)}
                                onkeydown={e => e.key === 'Enter' && activateRoot(id)}
                            >
                                <span class="group-icon">▤</span>
                                <span class="tab-name">{group.name}</span>
                                <button
                                    type="button"
                                    class="tab-close"
                                    aria-label={`Close group ${group.name}`}
                                    onclick={e => closeGroup(id, e)}
                                >
                                    ×
                                </button>
                            </div>
                        {:else if standalone}
                            <div
                                class="tab"
                                class:active={id === activeRootId}
                                tabindex="0"
                                role="button"
                                onclick={() => activateRoot(id)}
                                onkeydown={e => e.key === 'Enter' && activateRoot(id)}
                            >
                                <span class="tab-name">{standalone.target.name}</span>
                                <button
                                    type="button"
                                    class="tab-close"
                                    aria-label={`Close ${standalone.target.name}`}
                                    onclick={e => closeStandaloneTab(id, e)}
                                >
                                    ×
                                </button>
                            </div>
                        {/if}
                    {/each}

                    {#if availableLabelKeys.length > 0}
                        <label class="group-by">
                            Group by
                            <select bind:value={groupByLabelKey}>
                                <option value="">None</option>
                                {#each availableLabelKeys as key (key)}
                                    <option value={key}>{key}</option>
                                {/each}
                            </select>
                        </label>
                    {/if}
                </div>

                {#if activeGroup()}
                    {@const group = activeGroup()!}
                    <div class="tab-bar sub-tab-bar">
                        {#each openTargets.filter(t => t.groupId === group.id) as ot (ot.target.id)}
                            <div
                                class="tab sub-tab"
                                class:active={activeChildByGroup[group.id] === ot.target.id}
                                tabindex="0"
                                role="button"
                                onclick={() => activateChild(group.id, ot.target.id)}
                                onkeydown={e => e.key === 'Enter' && activateChild(group.id, ot.target.id)}
                            >
                                <span class="tab-name">{ot.target.name}</span>
                                <button
                                    type="button"
                                    class="tab-close"
                                    aria-label={`Close ${ot.target.name}`}
                                    onclick={e => closeChildTab(group.id, ot.target.id, e)}
                                >
                                    ×
                                </button>
                            </div>
                        {/each}
                    </div>
                {/if}

                <div class="tab-content">
                    {#each openTargets as ot (ot.target.id)}
                        <div class="tab-pane" class:hidden={!isVisible(ot)}>
                            {#if ot.target.kind === 'Rdp' || ot.target.kind === 'Vnc'}
                                <Desktop target={ot.target} />
                            {:else}
                                <Session target={ot.target} />
                            {/if}
                        </div>
                    {/each}
                </div>
            {:else}
                <div class="empty-state">
                    <p>Select a connection on the left to get started.</p>
                </div>
            {/if}
        </main>
    </div>
{/if}

<style>
    :global(body) {
        margin: 0;
        overflow: hidden;
        background: #12141c;
        font-family:
            system-ui,
            -apple-system,
            'Segoe UI',
            sans-serif;
    }

    .loading {
        color: #9aa4c0;
        padding: 40px;
        font-size: 14px;
    }

    .app {
        display: flex;
        height: 100vh;
    }

    main {
        flex: 1;
        min-width: 0;
        display: flex;
        flex-direction: column;
    }

    .tab-bar {
        flex-shrink: 0;
        display: flex;
        align-items: stretch;
        gap: 2px;
        background: #171a24;
        border-bottom: 1px solid #262b3a;
        overflow-x: auto;
    }

    .sub-tab-bar {
        background: #14161f;
        border-bottom: 1px solid #20242f;
    }

    .tab {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 8px 10px 8px 14px;
        color: #9aa4c0;
        font-size: 13px;
        cursor: pointer;
        border-bottom: 2px solid transparent;
        white-space: nowrap;
    }

    .sub-tab {
        font-size: 12px;
        padding: 6px 8px 6px 12px;
    }

    .tab:hover {
        background: #1f2433;
    }

    .tab.active {
        color: #dde3f0;
        border-bottom-color: #5b7cfa;
        background: #12141c;
    }

    .group-tab.active {
        border-bottom-color: #f5a623;
    }

    .group-icon {
        font-size: 11px;
        color: #f5a623;
    }

    .tab-close {
        border: none;
        background: transparent;
        color: #6b7280;
        cursor: pointer;
        font-size: 14px;
        line-height: 1;
        padding: 2px 4px;
    }

    .tab-close:hover {
        color: #f87171;
    }

    .group-by {
        margin-left: auto;
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 0 12px;
        color: #6b7280;
        font-size: 11px;
        white-space: nowrap;
    }

    .group-by select {
        background: #1f2433;
        color: #9aa4c0;
        border: 1px solid #2e3446;
        border-radius: 4px;
        font-size: 11px;
        padding: 2px 4px;
    }

    .tab-content {
        flex: 1;
        min-height: 0;
        position: relative;
    }

    .tab-pane {
        position: absolute;
        inset: 0;
    }

    .tab-pane.hidden {
        display: none;
    }

    .empty-state {
        flex: 1;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #4b5163;
        font-size: 14px;
    }
</style>
