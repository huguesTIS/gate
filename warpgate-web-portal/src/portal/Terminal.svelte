<script lang="ts">
    import { FitAddon } from '@xterm/addon-fit'
    import { Terminal as XTerm } from '@xterm/xterm'
    import '@xterm/xterm/css/xterm.css'
    import { onDestroy, onMount } from 'svelte'

    interface Props {
        readOnly?: boolean
        onInput?: (data: Uint8Array) => void
        onResize?: (cols: number, rows: number) => void
    }
    let { readOnly = false, onInput, onResize }: Props = $props()

    let container: HTMLDivElement
    let term: XTerm
    let fitAddon: FitAddon

    export function write(data: Uint8Array): void {
        term?.write(data)
    }

    export function fit(): void {
        fitAddon?.fit()
    }

    export function getSize(): { cols: number; rows: number } | null {
        return term ? { cols: term.cols, rows: term.rows } : null
    }

    onMount(() => {
        term = new XTerm({
            cursorBlink: true,
            fontFamily: "'Cascadia Code', 'Fira Code', monospace",
            fontSize: 14,
            theme: {
                background: '#12141c',
                foreground: '#dde3f0',
            },
        })
        fitAddon = new FitAddon()
        term.loadAddon(fitAddon)
        term.open(container)
        fitAddon.fit()

        // Paste already works with no extra code: xterm.js's own hidden textarea
        // captures the native paste event and feeds it through `onData` below (same
        // path as typing). Copy is the one half xterm.js deliberately leaves to the
        // consumer (`getSelection()`'s doc: "useful for implementing copy behavior
        // outside of xterm.js") — Ctrl+C only means copy when there's a selection;
        // otherwise it must still reach the shell as SIGINT.
        term.attachCustomKeyEventHandler(event => {
            if (event.type !== 'keydown') {
                return true
            }
            const isMac = navigator.platform.toLowerCase().includes('mac')
            const modifierPressed = isMac ? event.metaKey : event.ctrlKey
            if (modifierPressed && event.key.toLowerCase() === 'c' && term.hasSelection()) {
                navigator.clipboard?.writeText(term.getSelection()).catch(() => {})
                return false
            }
            return true
        })

        term.onData(data => {
            if (!readOnly) {
                onInput?.(new TextEncoder().encode(data))
            }
        })
        term.onResize(({ cols, rows }) => onResize?.(cols, rows))

        const resizeObserver = new ResizeObserver(() => fitAddon.fit())
        resizeObserver.observe(container)

        return () => resizeObserver.disconnect()
    })

    onDestroy(() => {
        term?.dispose()
    })
</script>

<div class="terminal-container" bind:this={container}></div>

<style>
    .terminal-container {
        width: 100%;
        height: 100%;
    }
</style>
