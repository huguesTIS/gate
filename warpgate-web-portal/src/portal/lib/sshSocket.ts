// Wire protocol for `/@warpgate/api/web-ssh/sessions/:id/stream`, defined server-side in
// `warpgate-web-ssh/src/protocol.rs`. Mirrors `warpgate-web/src/gateway/WebSsh.svelte` —
// deliberately not shared code (see ARCHITECTURE_TECHNIQUE.md §13: this crate has its own
// independent frontend, no cross-package coupling with `warpgate-web`).

export type ClientMessage =
    | { type: 'open_channel'; cols?: number; rows?: number }
    | { type: 'input'; channel_id: string; data: string }
    | { type: 'resize'; channel_id: string; cols: number; rows: number }
    | { type: 'close_channel'; channel_id: string }
    | { type: 'accept_host_key' }
    | { type: 'reject_host_key' }

export type ServerMessage =
    | { type: 'connection_state'; state: string }
    | { type: 'output'; channel_id: string; data: string }
    | { type: 'channel_opened'; channel_id: string }
    | { type: 'channel_closed'; channel_id: string }
    | { type: 'eof'; channel_id: string }
    | { type: 'exit_status'; channel_id: string; code: number }
    | { type: 'error'; message: string }
    | {
          type: 'host_key_unknown'
          host: string
          port: number
          key_type: string
          key_base64: string
      }

export function bytesToBase64(bytes: Uint8Array): string {
    let binary = ''
    const chunkSize = 0x8000
    for (let i = 0; i < bytes.length; i += chunkSize) {
        const chunk = bytes.subarray(i, i + chunkSize)
        binary += String.fromCharCode(...chunk)
    }
    return btoa(binary)
}

export function base64ToBytes(data: string): Uint8Array {
    return Uint8Array.from(atob(data), c => c.charCodeAt(0))
}

export class SshSocket {
    private ws: WebSocket

    constructor(
        sessionId: string,
        private onMessage: (msg: ServerMessage) => void,
        private onClose: () => void,
    ) {
        this.ws = new WebSocket(
            `wss://${location.host}/@warpgate/api/web-ssh/sessions/${sessionId}/stream`,
        )
        this.ws.addEventListener('message', ev => {
            this.onMessage(JSON.parse(ev.data as string) as ServerMessage)
        })
        this.ws.addEventListener('close', () => this.onClose())
    }

    send(msg: ClientMessage): void {
        if (this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(msg))
        }
    }

    close(): void {
        this.ws.close()
    }
}
