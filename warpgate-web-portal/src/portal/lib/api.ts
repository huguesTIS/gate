// Hand-rolled minimal client against the existing "Warpgate user API"
// (`warpgate-protocol-http/src/api/*`) — same endpoints the classic gateway app
// (`warpgate-web/src/gateway`) already uses, reached same-origin so the session
// cookie set by `/@warpgate/login` is sent automatically. See
// ARCHITECTURE_TECHNIQUE.md §13 for why this crate doesn't generate the full
// OpenAPI TS client the classic app uses: kept out of scope for this first pass.

const API_BASE = '/@warpgate/api'

export class ApiError extends Error {
    constructor(
        public status: number,
        message: string,
    ) {
        super(message)
    }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
    const res = await fetch(`${API_BASE}${path}`, {
        ...init,
        credentials: 'same-origin',
        headers: {
            ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
            ...init?.headers,
        },
    })
    if (!res.ok) {
        throw new ApiError(res.status, `${path}: HTTP ${res.status}`)
    }
    if (res.status === 204) {
        return undefined as T
    }
    return (await res.json()) as T
}

export interface Info {
    username?: string
    web_clients_enabled: boolean
}

export function getInfo(): Promise<Info> {
    return request<Info>('/info')
}

export type TargetKind =
    | 'Http'
    | 'Kubernetes'
    | 'MySql'
    | 'Ssh'
    | 'Postgres'
    | 'Mssql'
    | 'Vnc'
    | 'Rdp'

export interface GroupInfo {
    id: string
    name: string
    color?: string
}

export interface TargetSnapshot {
    id: string
    name: string
    description: string
    kind: TargetKind
    external_host?: string
    group?: GroupInfo
    default_database_name?: string
}

export function getTargets(search?: string): Promise<TargetSnapshot[]> {
    const qs = search ? `?search=${encodeURIComponent(search)}` : ''
    return request<TargetSnapshot[]>(`/targets${qs}`)
}

export interface TargetLabelSnapshot {
    target_id: string
    key: string
    value: string
}

export function getTargetLabels(): Promise<TargetLabelSnapshot[]> {
    return request<TargetLabelSnapshot[]>('/target-labels')
}

export interface WebSshSessionCreated {
    session_id: string
}

export function createWebSshSession(targetId: string): Promise<WebSshSessionCreated> {
    return request<WebSshSessionCreated>('/web-ssh/sessions', {
        method: 'POST',
        body: JSON.stringify({ target_id: targetId }),
    })
}

export function deleteWebSshSession(sessionId: string): Promise<void> {
    return request<void>(`/web-ssh/sessions/${sessionId}`, { method: 'DELETE' })
}

export interface WebDesktopSessionCreated {
    session_id: string
}

export function createWebDesktopSession(
    targetId: string,
    width?: number,
    height?: number,
): Promise<WebDesktopSessionCreated> {
    return request<WebDesktopSessionCreated>('/web-desktop/sessions', {
        method: 'POST',
        body: JSON.stringify({ target_id: targetId, width, height }),
    })
}

export interface SessionHistoryEntry {
    id: string
    target_name?: string
    protocol: string
    started: string
    ended?: string
    has_recording: boolean
}

export function getMySessions(): Promise<SessionHistoryEntry[]> {
    return request<SessionHistoryEntry[]>('/my-sessions')
}

export function deleteWebDesktopSession(sessionId: string): Promise<void> {
    return request<void>(`/web-desktop/sessions/${sessionId}`, { method: 'DELETE' })
}

export function getFavorites(): Promise<string[]> {
    return request<string[]>('/favorites')
}

export function addFavorite(targetId: string): Promise<void> {
    return request<void>(`/favorites/${targetId}`, { method: 'PUT' })
}

export function removeFavorite(targetId: string): Promise<void> {
    return request<void>(`/favorites/${targetId}`, { method: 'DELETE' })
}

export interface SavedView {
    id: string
    name: string
    filter_json?: { search?: string } | null
    target_ids: string[]
    owned: boolean
}

export interface SavedViewRequest {
    name: string
    filter_json: { search?: string } | null
    target_ids: string[]
}

export function getSavedViews(): Promise<SavedView[]> {
    return request<SavedView[]>('/saved-views')
}

export function createSavedView(body: SavedViewRequest): Promise<SavedView> {
    return request<SavedView>('/saved-views', {
        method: 'POST',
        body: JSON.stringify(body),
    })
}

export function deleteSavedView(viewId: string): Promise<void> {
    return request<void>(`/saved-views/${viewId}`, { method: 'DELETE' })
}

export function duplicateSavedView(viewId: string): Promise<SavedView> {
    return request<SavedView>(`/saved-views/${viewId}/duplicate`, { method: 'POST' })
}
