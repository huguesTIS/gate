<script lang="ts">
    import { onDestroy, onMount } from 'svelte'
    import { ApiError, createWebSshSession, deleteWebSshSession, type TargetSnapshot } from './lib/api'
    import { base64ToBytes, bytesToBase64, SshSocket, type ServerMessage } from './lib/sshSocket'
    import Terminal from './Terminal.svelte'

    interface Props {
        target: TargetSnapshot
    }
    let { target }: Props = $props()

    let terminal: Terminal
    let socket: SshSocket | undefined
    let channelId: string | null = $state(null)
    let connState: 'connecting' | 'connected' | 'closed' | 'error' = $state('connecting')
    let error: string | null = $state(null)
    let pendingHostKey: Extract<ServerMessage, { type: 'host_key_unknown' }> | null =
        $state(null)
    let sessionId: string | undefined

    function onMessage(msg: ServerMessage) {
        switch (msg.type) {
            case 'channel_opened':
                channelId = msg.channel_id
                connState = 'connected'
                break
            case 'output':
                if (msg.channel_id === channelId) {
                    terminal?.write(base64ToBytes(msg.data))
                }
                break
            case 'channel_closed':
            case 'eof':
                connState = 'closed'
                break
            case 'exit_status':
                terminal?.write(
                    new TextEncoder().encode(`\r\n[Process exited with code ${msg.code}]\r\n`),
                )
                break
            case 'error':
                connState = 'error'
                error = msg.message
                break
            case 'host_key_unknown':
                pendingHostKey = msg
                break
        }
    }

    async function connect() {
        // A retry after a dropped/errored connection leaves the previous session
        // dangling server-side otherwise (its onDestroy cleanup only fires when this
        // component unmounts, not on retry).
        socket?.close()
        if (sessionId) {
            deleteWebSshSession(sessionId).catch(() => {})
            sessionId = undefined
        }
        channelId = null

        connState = 'connecting'
        error = null
        try {
            const created = await createWebSshSession(target.id)
            socket = new SshSocket(
                created.session_id,
                onMessage,
                () => {
                    if (connState !== 'closed') {
                        connState = 'error'
                        error = error ?? 'Connection lost'
                    }
                },
            )
            socket.send({ type: 'open_channel', cols: 80, rows: 24 })
            sessionId = created.session_id
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

    onMount(connect)

    onDestroy(() => {
        socket?.close()
        if (sessionId) {
            deleteWebSshSession(sessionId).catch(() => {})
        }
    })
</script>

<div class="session">
    <div class="session-header">
        <span class="target-name">{target.name}</span>
        <span class="state" class:connected={connState === 'connected'}>{connState}</span>
    </div>

    <div class="session-body">
        <Terminal
            bind:this={terminal}
            readOnly={connState !== 'connected'}
            onInput={data =>
                channelId &&
                socket?.send({ type: 'input', channel_id: channelId, data: bytesToBase64(data) })}
            onResize={(cols, rows) =>
                channelId && socket?.send({ type: 'resize', channel_id: channelId, cols, rows })}
        />

        {#if error}
            <div class="overlay">
                <div class="error-box">
                    <p>{error}</p>
                    <button type="button" class="retry" onclick={connect}>Retry</button>
                </div>
            </div>
        {/if}

        {#if pendingHostKey}
            <div class="overlay">
                <div class="host-key-box">
                    <p>
                        No trusted {pendingHostKey.key_type} key for
                        {pendingHostKey.host}:{pendingHostKey.port}. Trust this key?
                    </p>
                    <code>{pendingHostKey.key_type} {pendingHostKey.key_base64}</code>
                    <div class="actions">
                        <button
                            type="button"
                            onclick={() => {
                                socket?.send({ type: 'reject_host_key' })
                                pendingHostKey = null
                            }}
                        >
                            Reject
                        </button>
                        <button
                            type="button"
                            class="primary"
                            onclick={() => {
                                socket?.send({ type: 'accept_host_key' })
                                pendingHostKey = null
                            }}
                        >
                            Accept and connect
                        </button>
                    </div>
                </div>
            </div>
        {/if}
    </div>
</div>

<style>
    .session {
        display: flex;
        flex-direction: column;
        height: 100%;
        flex: 1;
        min-width: 0;
    }

    .session-header {
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

    .session-body {
        flex: 1;
        position: relative;
        background: #12141c;
        padding: 8px;
        box-sizing: border-box;
        min-height: 0;
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

    .host-key-box {
        background: #171a24;
        border: 1px solid #2e3446;
        padding: 20px;
        border-radius: 8px;
        max-width: 480px;
        color: #dde3f0;
    }

    .host-key-box code {
        display: block;
        margin: 10px 0;
        word-break: break-all;
        color: #9aa4c0;
    }

    .actions {
        display: flex;
        gap: 8px;
        justify-content: flex-end;
        margin-top: 12px;
    }

    .actions button {
        padding: 6px 14px;
        border-radius: 6px;
        border: 1px solid #2e3446;
        background: #1f2433;
        color: #dde3f0;
        cursor: pointer;
    }

    .actions button.primary {
        background: #3556e0;
        border-color: #3556e0;
    }
</style>
