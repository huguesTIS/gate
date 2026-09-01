// Framebuffer rendering for desktop (RDP/VNC) sessions. Ported from
// `warpgate-web/src/common/desktopCanvas.ts` (proven logic — the RDP/VNC pipeline has a
// documented history of subtle tearing/ordering bugs, see ARCHITECTURE_TECHNIQUE.md §10 —
// not reimplemented from scratch). Kept deliberately independent per this crate's own
// deps/no-cross-package-coupling rule (ARCHITECTURE_TECHNIQUE.md §13).

export interface Rect {
    x: number
    y: number
    width: number
    height: number
}

type FrameImageData = string | Uint8Array<ArrayBuffer>

export type DesktopFrame =
    | { type: 'resize'; width: number; height: number }
    | { type: 'raw_image'; rect: Rect; data: FrameImageData }
    | {
          type: 'png_image'
          rect: Rect
          keyframe?: boolean
          data: FrameImageData
      }
    | { type: 'jpeg_image'; rect: Rect; data: FrameImageData }
    | { type: 'copy_rect'; dst: Rect; src_x: number; src_y: number }
    | { type: 'cursor'; rect: Rect; data: FrameImageData }

export type PreparedFrame = DesktopFrame & {
    bitmap?: Promise<ImageBitmap | null>
}

export function isIncrementalFrame(msg: DesktopFrame): boolean {
    switch (msg.type) {
        case 'raw_image':
        case 'jpeg_image':
        case 'copy_rect':
        case 'cursor':
            return true
        case 'png_image':
            return !msg.keyframe
        case 'resize':
            return false
    }
}

export function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
    const binary = atob(b64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i)
    }
    return bytes
}

function toBytes(data: FrameImageData): Uint8Array<ArrayBuffer> {
    return typeof data === 'string' ? base64ToBytes(data) : data
}

export function ensureCanvasSize(canvas: HTMLCanvasElement, width: number, height: number): void {
    if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width
        canvas.height = height
    }
}

function ensureForRect(canvas: HTMLCanvasElement, rect: Rect): void {
    ensureCanvasSize(
        canvas,
        Math.max(canvas.width, rect.x + rect.width),
        Math.max(canvas.height, rect.y + rect.height),
    )
}

function drawRaw(ctx: CanvasRenderingContext2D, rect: Rect, bgra: Uint8Array): void {
    const count = rect.width * rect.height
    const rgba = new Uint8ClampedArray(count * 4)
    for (let i = 0; i < count; i++) {
        const s = i * 4
        // server sends BGRA, canvas wants RGBA
        rgba[s] = bgra[s + 2] ?? 0
        rgba[s + 1] = bgra[s + 1] ?? 0
        rgba[s + 2] = bgra[s] ?? 0
        rgba[s + 3] = 255
    }
    ctx.putImageData(new ImageData(rgba, rect.width, rect.height), rect.x, rect.y)
}

function decodeBlob(data: FrameImageData, mime: string): Promise<ImageBitmap | null> {
    return createImageBitmap(new Blob([toBytes(data)], { type: mime })).catch(() => null)
}

function startDecode(msg: DesktopFrame): Promise<ImageBitmap | null> | undefined {
    switch (msg.type) {
        case 'png_image':
            return decodeBlob(msg.data, 'image/png')
        case 'jpeg_image':
            return decodeBlob(msg.data, 'image/jpeg')
        default:
            return undefined
    }
}

export function decodeDesktopFrame(msg: DesktopFrame): PreparedFrame {
    const bitmap = startDecode(msg)
    return bitmap ? { ...msg, bitmap } : msg
}

// Serializes paints per canvas: createImageBitmap doesn't resolve in issue order on every
// engine, so painting as decodes land would leave stale pixels on top of newer ones.
const paintChains = new WeakMap<HTMLCanvasElement, Promise<void>>()

export function applyDesktopFrame(
    canvas: HTMLCanvasElement,
    ctx: CanvasRenderingContext2D,
    msg: PreparedFrame,
): Promise<void> {
    const previous = paintChains.get(canvas) ?? Promise.resolve()
    const result = previous.then(() => paintFrame(canvas, ctx, msg))
    paintChains.set(
        canvas,
        result.catch(() => undefined),
    )
    return result
}

async function paintFrame(
    canvas: HTMLCanvasElement,
    ctx: CanvasRenderingContext2D,
    msg: PreparedFrame,
): Promise<void> {
    switch (msg.type) {
        case 'resize':
            ensureCanvasSize(canvas, msg.width, msg.height)
            break
        case 'raw_image':
            ensureForRect(canvas, msg.rect)
            drawRaw(ctx, msg.rect, toBytes(msg.data))
            break
        case 'png_image':
        case 'jpeg_image': {
            const bitmap = await (msg.bitmap ?? startDecode(msg))
            if (bitmap) {
                ensureForRect(canvas, msg.rect)
                ctx.drawImage(bitmap, msg.rect.x, msg.rect.y)
                bitmap.close()
            }
            break
        }
        case 'copy_rect':
            ctx.drawImage(
                canvas,
                msg.src_x,
                msg.src_y,
                msg.dst.width,
                msg.dst.height,
                msg.dst.x,
                msg.dst.y,
                msg.dst.width,
                msg.dst.height,
            )
            break
        case 'cursor':
            break
        default:
            return msg satisfies never
    }
}
