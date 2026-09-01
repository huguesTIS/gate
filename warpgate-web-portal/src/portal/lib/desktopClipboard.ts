// Bidirectional clipboard sync for the web desktop viewer. Ported from
// `warpgate-web/src/common/desktopClipboard.ts` verbatim (subtle Mac/Windows paste-combo
// and held-modifier handling — not worth re-deriving).
//
// Remote -> local: text the target copied is written to the local clipboard.
// Local -> remote: the browser's `paste` event is the only way to read the local
// clipboard without a permission prompt, so the platform paste combo is left
// alone in the key handler and replayed as a synthesised Ctrl+V after the text
// has been forwarded.

export interface SyntheticKey {
    keysym: number
    scancode: number
    extended: boolean
}

const CONTROL_KEY: SyntheticKey = {
    keysym: 0xffe3,
    scancode: 0x1d,
    extended: false,
}
const V_KEY: SyntheticKey = { keysym: 0x76, scancode: 0x2f, extended: false }
// Left Win / Super.
const META_KEY: SyntheticKey = {
    keysym: 0xffeb,
    scancode: 0x5b,
    extended: true,
}

export class DesktopClipboard {
    private readonly isMac = /Mac|iPhone|iPad/.test(navigator.platform)

    private controlHeld = false
    private metaHeld = false

    private pendingRemoteText: string | null = null

    constructor(
        private readonly sendText: (text: string) => void,
        private readonly sendKey: (key: SyntheticKey, down: boolean) => void,
    ) {}

    onRemoteCopy(text: string): void {
        this.pendingRemoteText = text
        this.flush()
    }

    flush(): void {
        const text = this.pendingRemoteText
        if (text === null) {
            return
        }
        navigator.clipboard
            ?.writeText(text)
            .then(() => {
                if (this.pendingRemoteText === text) {
                    this.pendingRemoteText = null
                }
            })
            .catch(() => {})
    }

    onKey(e: KeyboardEvent, down: boolean): void {
        if (down) {
            this.flush()
        }
        if (e.key === 'Control') {
            this.controlHeld = down
        }
        if (e.key === 'Meta') {
            this.metaHeld = down
        }
    }

    onBlur(): void {
        this.controlHeld = false
        this.metaHeld = false
    }

    isPasteCombo(e: KeyboardEvent): boolean {
        return (
            (this.isMac ? e.metaKey : e.ctrlKey) &&
            (e.code === 'KeyV' || e.key.toLowerCase() === 'v')
        )
    }

    onPaste(e: ClipboardEvent): void {
        e.preventDefault()
        const text = e.clipboardData?.getData('text/plain')
        if (text) {
            if (text !== this.pendingRemoteText) {
                this.sendText(text)
            }
            this.pendingRemoteText = null
        }
        this.flush()
        this.sendKey(CONTROL_KEY, true)
        if (this.metaHeld) {
            this.sendKey(META_KEY, false)
        }
        this.sendKey(V_KEY, true)
        this.sendKey(V_KEY, false)
        if (!this.controlHeld) {
            this.sendKey(CONTROL_KEY, false)
        }
    }
}
