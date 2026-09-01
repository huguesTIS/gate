<script lang="ts">
    import { onDestroy, onMount } from 'svelte'
    import {
        ApiError,
        createWebDesktopSession,
        deleteWebDesktopSession,
        type TargetSnapshot,
    } from './lib/api'
    import {
        applyDesktopFrame,
        decodeDesktopFrame,
        isIncrementalFrame,
        type DesktopFrame,
        type PreparedFrame,
        type Rect,
    } from './lib/desktopCanvas'
    import { DesktopClipboard } from './lib/desktopClipboard'
    import { codeToScancode } from './lib/desktopInput'

    interface Props {
        target: TargetSnapshot
    }
    let { target }: Props = $props()

    // Wire protocol mirrors `warpgate-web-desktop/src/protocol.rs`'s `ServerMessage` —
    // pixel-carrying variants arrive as compact binary, everything else as JSON text (see
    // that file's `ws_payload`). Ported rendering/input logic from
    // `warpgate-web/src/gateway/WebDesktop.svelte`; see `lib/desktopCanvas.ts`'s header.
    type ServerMessage =
        | { type: 'connection_state'; state: string }
        | { type: 'resize'; width: number; height: number }
        | { type: 'raw_image'; rect: Rect; data: string }
        | { type: 'jpeg_image'; rect: Rect; data: string }
        | { type: 'copy_rect'; dst: Rect; src_x: number; src_y: number }
        | { type: 'cursor'; rect: Rect; data: string }
        | { type: 'clipboard'; text: string }
        | { type: 'bell' }
        | { type: 'error'; message: string }

    let canvas: HTMLCanvasElement | undefined = $state()
    let canvasArea: HTMLDivElement | undefined = $state()
    let rootElement: HTMLDivElement | undefined = $state()
    let painted = $state(false)
    let isFullscreen = $state(false)
    let ctx: CanvasRenderingContext2D | null = null
    let connState: 'connecting' | 'connected' | 'closed' | 'error' = $state('connecting')
    let error: string | null = $state(null)
    let sessionId: string | undefined

    const MAX_PENDING_FRAMES = 360
    let pendingFrames: PreparedFrame[] = []
    let draining = false
    let rafHandle: number | null = null
    let pendingPointer: { x: number; y: number; buttons: number } | null = null
    let ws: WebSocket | undefined
    let resizeObserver: ResizeObserver | undefined

    function send(msg: unknown): void {
        if (ws?.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(msg))
        }
    }

    const clipboard = new DesktopClipboard(
        text => send({ type: 'clipboard', text }),
        (key, down) => send({ type: 'key_event', ...key, down }),
    )

    function viewportSize(): { width: number; height: number } | null {
        const width = Math.floor(canvasArea?.clientWidth ?? 0)
        const height = Math.floor(canvasArea?.clientHeight ?? 0)
        if (width < 1 || height < 1) {
            return null
        }
        return { width, height }
    }

    // `[kind: u8][x,y,w,h: u16 LE][pixels…]`
    function decodeBinaryFrame(buf: ArrayBuffer): DesktopFrame | null {
        if (buf.byteLength < 9) {
            return null
        }
        const view = new DataView(buf)
        const rect: Rect = {
            x: view.getUint16(1, true),
            y: view.getUint16(3, true),
            width: view.getUint16(5, true),
            height: view.getUint16(7, true),
        }
        const data = new Uint8Array(buf, 9)
        switch (view.getUint8(0)) {
            case 1:
                return { type: 'raw_image', rect, data }
            case 2:
                return { type: 'jpeg_image', rect, data }
            case 3:
                // Cursor sprites aren't composited onto the canvas.
                return null
            case 4:
                return { type: 'png_image', rect, data, keyframe: true }
            case 5:
                return { type: 'png_image', rect, data }
            default:
                return null
        }
    }

    function queueFrame(frame: DesktopFrame): void {
        pendingFrames.push(decodeDesktopFrame(frame))
        if (pendingFrames.length > MAX_PENDING_FRAMES) {
            const idx = pendingFrames.findIndex(isIncrementalFrame)
            const [dropped] = pendingFrames.splice(idx === -1 ? 0 : idx, 1)
            void dropped?.bitmap?.then(bitmap => bitmap?.close())
        }
    }

    async function drain(): Promise<void> {
        if (draining || !canvas || !ctx) {
            return
        }
        draining = true
        try {
            for (let budget = pendingFrames.length; budget > 0; budget--) {
                const frame = pendingFrames.shift()
                if (!frame) {
                    break
                }
                await applyDesktopFrame(canvas, ctx, frame)
                painted = true
            }
        } finally {
            draining = false
        }
    }

    function rafTick(): void {
        void drain()
        if (pendingPointer) {
            send({ type: 'pointer_event', ...pendingPointer })
            pendingPointer = null
        }
        rafHandle = requestAnimationFrame(rafTick)
    }

    function onWsMessage(ev: MessageEvent): void {
        if (ev.data instanceof ArrayBuffer) {
            const frame = decodeBinaryFrame(ev.data)
            if (frame) {
                queueFrame(frame)
            }
            return
        }
        const msg = JSON.parse(ev.data as string) as ServerMessage
        switch (msg.type) {
            case 'connection_state':
                if (msg.state === 'connected') {
                    connState = 'connected'
                    const size = viewportSize()
                    if (size) {
                        send({ type: 'resize', ...size })
                    }
                } else if (msg.state === 'disconnected') {
                    connState = 'closed'
                }
                break
            case 'clipboard':
                clipboard.onRemoteCopy(msg.text)
                break
            case 'bell':
                break
            case 'error':
                connState = 'error'
                error = msg.message
                break
            default:
                queueFrame(msg)
        }
    }

    async function connect(): Promise<void> {
        // Same reasoning as Session.svelte's connect(): a retry after a dropped/errored
        // connection must clean up the previous session, or it dangles server-side.
        ws?.close()
        if (sessionId) {
            deleteWebDesktopSession(sessionId).catch(() => {})
            sessionId = undefined
        }

        connState = 'connecting'
        error = null
        painted = false
        try {
            const size = viewportSize()
            const created = await createWebDesktopSession(target.id, size?.width, size?.height)
            sessionId = created.session_id
            ws = new WebSocket(
                `wss://${location.host}/@warpgate/api/web-desktop/sessions/${created.session_id}/stream`,
            )
            ws.binaryType = 'arraybuffer'
            ws.addEventListener('message', onWsMessage)
            ws.addEventListener('close', () => {
                if (connState !== 'closed') {
                    connState = 'error'
                    error = error ?? 'Connection lost'
                }
            })
        } catch (e) {
            connState = 'error'
            error =
                e instanceof ApiError
                    ? `Could not open session (HTTP ${e.status})`
                    : e instanceof Error
                      ? e.message
                      : 'Could not open session'
        }
    }

    function toggleFullscreen(): void {
        if (document.fullscreenElement) {
            void document.exitFullscreen()
        } else {
            void rootElement?.requestFullscreen()
        }
    }

    function rfbButtons(e: MouseEvent): number {
        let mask = 0
        if (e.buttons & 1) mask |= 1
        if (e.buttons & 4) mask |= 2
        if (e.buttons & 2) mask |= 4
        return mask
    }

    function canvasCoords(e: MouseEvent): { x: number; y: number } {
        if (!canvas) {
            return { x: 0, y: 0 }
        }
        const r = canvas.getBoundingClientRect()
        const x = Math.round((e.clientX - r.left) * (canvas.width / r.width))
        const y = Math.round((e.clientY - r.top) * (canvas.height / r.height))
        return { x: Math.max(0, x), y: Math.max(0, y) }
    }

    function onPointerMove(e: MouseEvent): void {
        const { x, y } = canvasCoords(e)
        pendingPointer = { x, y, buttons: rfbButtons(e) }
    }

    function onPointerButton(e: MouseEvent): void {
        clipboard.flush()
        const { x, y } = canvasCoords(e)
        pendingPointer = null
        send({ type: 'pointer_event', x, y, buttons: rfbButtons(e) })
    }

    function onWheel(e: WheelEvent): void {
        e.preventDefault()
        const { x, y } = canvasCoords(e)
        if (e.deltaY !== 0) {
            send({ type: 'wheel_event', x, y, vertical: true, delta: e.deltaY < 0 ? 1 : -1 })
        }
        if (e.deltaX !== 0) {
            send({ type: 'wheel_event', x, y, vertical: false, delta: e.deltaX > 0 ? 1 : -1 })
        }
    }

    function keysym(e: KeyboardEvent): number | null {
        const special: Record<string, number> = {
            Backspace: 0xff08,
            Tab: 0xff09,
            Enter: 0xff0d,
            Escape: 0xff1b,
            Delete: 0xffff,
            Home: 0xff50,
            ArrowLeft: 0xff51,
            ArrowUp: 0xff52,
            ArrowRight: 0xff53,
            ArrowDown: 0xff54,
            PageUp: 0xff55,
            PageDown: 0xff56,
            End: 0xff57,
            Insert: 0xff63,
            Shift: 0xffe1,
            Control: 0xffe3,
            Alt: 0xffe9,
            Meta: 0xffeb,
            CapsLock: 0xffe5,
            ' ': 0x0020,
        }
        const specialKey = special[e.key]
        if (specialKey) {
            return specialKey
        }
        if (e.key.startsWith('F') && e.key.length <= 3 && !Number.isNaN(Number(e.key.slice(1)))) {
            return 0xffbe + (Number(e.key.slice(1)) - 1)
        }
        if (e.key.length === 1) {
            return e.key.charCodeAt(0)
        }
        return null
    }

    function onKey(e: KeyboardEvent, down: boolean): void {
        if (connState !== 'connected') {
            return
        }
        clipboard.onKey(e, down)
        if (clipboard.isPasteCombo(e)) {
            return
        }
        const ks = keysym(e)
        const scancode = codeToScancode(e.code)
        if (ks === null && !scancode) {
            return
        }
        e.preventDefault()
        send({
            type: 'key_event',
            keysym: ks,
            scancode: scancode?.code ?? null,
            extended: scancode?.extended ?? false,
            down,
        })
    }

    function onPaste(e: ClipboardEvent): void {
        if (connState !== 'connected') {
            return
        }
        clipboard.onPaste(e)
    }

    onMount(() => {
        if (canvas) {
            ctx = canvas.getContext('2d', { alpha: false })
            canvas.focus()
        }
        if (canvasArea) {
            resizeObserver = new ResizeObserver(() => {
                const size = viewportSize()
                if (size && connState === 'connected') {
                    send({ type: 'resize', ...size })
                }
            })
            resizeObserver.observe(canvasArea)
        }
        rafHandle = requestAnimationFrame(rafTick)
        connect()
    })

    onDestroy(() => {
        ws?.close()
        resizeObserver?.disconnect()
        if (rafHandle !== null) {
            cancelAnimationFrame(rafHandle)
        }
        if (sessionId) {
            deleteWebDesktopSession(sessionId).catch(() => {})
        }
    })
</script>

<svelte:document onfullscreenchange={() => (isFullscreen = !!document.fullscreenElement)} />

<div class="desktop" bind:this={rootElement}>
    <div class="desktop-header">
        <span class="target-name">{target.name}</span>
        <span class="state" class:connected={connState === 'connected'}>{connState}</span>
        <button
            type="button"
            class="fullscreen-toggle"
            title={isFullscreen ? 'Exit fullscreen' : 'Fullscreen'}
            onclick={toggleFullscreen}
        >
            {isFullscreen ? '⤦' : '⤢'}
        </button>
    </div>

    <div bind:this={canvasArea} class="canvas-area">
        <canvas
            bind:this={canvas}
            class:painted
            tabindex="0"
            onkeydown={e => onKey(e, true)}
            onkeyup={e => onKey(e, false)}
            onpaste={onPaste}
            onblur={() => clipboard.onBlur()}
            onmousemove={onPointerMove}
            onmousedown={onPointerButton}
            onmouseup={onPointerButton}
            onwheel={onWheel}
            oncontextmenu={e => e.preventDefault()}
        ></canvas>

        {#if error}
            <div class="overlay">
                <div class="error-box">
                    <p>{error}</p>
                    <button type="button" class="retry" onclick={connect}>Retry</button>
                </div>
            </div>
        {/if}
    </div>
</div>

<style>
    .desktop {
        display: flex;
        flex-direction: column;
        height: 100%;
    }

    .desktop-header {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 10px 16px;
        border-bottom: 1px solid #262b3a;
        background: #171a24;
    }

    .target-name {
        font-weight: 600;
        color: #dde3f0;
    }

    .state {
        font-size: 12px;
        color: #f5a623;
        text-transform: capitalize;
    }

    .state.connected {
        color: #4ade80;
    }

    .fullscreen-toggle {
        margin-left: auto;
        border: none;
        background: transparent;
        color: #9aa4c0;
        cursor: pointer;
        font-size: 16px;
    }

    .fullscreen-toggle:hover {
        color: #dde3f0;
    }

    .canvas-area {
        flex: 1;
        min-height: 0;
        position: relative;
        display: flex;
        align-items: center;
        justify-content: center;
        overflow: auto;
        background: black;
    }

    canvas {
        image-rendering: pixelated;
        max-width: 100%;
        max-height: 100%;
        outline: none;
        opacity: 0;
        transition: opacity 0.5s ease-in-out;
    }

    canvas.painted {
        opacity: 1;
    }

    .overlay {
        position: absolute;
        inset: 0;
        display: flex;
        align-items: center;
        justify-content: center;
        background: rgba(10, 12, 18, 0.85);
    }

    .error-box {
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        gap: 10px;
        background: #2a1a1a;
        border: 1px solid #7f1d1d;
        color: #fca5a5;
        padding: 16px 20px;
        border-radius: 8px;
        max-width: 400px;
    }

    .error-box p {
        margin: 0;
    }

    .error-box .retry {
        padding: 6px 14px;
        border-radius: 6px;
        border: 1px solid #7f1d1d;
        background: #3a1f1f;
        color: #fca5a5;
        cursor: pointer;
    }

    .error-box .retry:hover {
        background: #4a2626;
    }
</style>
