Fork of `ironrdp-server` 0.13.0.

## Surface the client's negotiated keyboard layout to `CredentialValidator`

Discussed in `ARCHITECTURE_TECHNIQUE.md` §10 ("RDP + Requester par écran de saisie
in-session"): the in-session credential-entry screen reads raw scancodes from the viewer and
maps them to characters assuming a US QWERTY physical layout, which types the wrong characters
on any other client keyboard layout (confirmed with a French AZERTY client — a correct AD
password came out scrambled).

`ironrdp-acceptor`'s `AcceptorResult` already carries exactly the data needed —
`pub keyboard_layout: u32`, the low word of the client's Windows locale identifier from its GCC
Client Core Data, with a doc comment literally inviting this use ("Servers can use it to pick a
server-side keyboard layout matching the client"). `ironrdp-server` receives this `AcceptorResult`
in `client_accepted` but never surfaces `keyboard_layout` anywhere in its public API — not on
`RdpServer`, not on any handler trait. No newer release fixes this (0.13.0 is upstream's latest
as of 21 Aug 2026).

`warpgate.patch` adds a `keyboard_layout: u32` parameter to `CredentialValidator::validate`,
threaded through from `result.keyboard_layout` at the one call site (`client_accepted`) — chosen
over a new callback because it's already the one hook the embedder gets once per connection with
I/O access, and Warpgate already implements this trait (`warpgate-protocol-rdp/src/server/rdp.rs`).
Unrelated to credential validation itself; riding along on this call is a pragmatic reuse, not a
claim that keyboard layout belongs conceptually with credentials.

When re-vendoring: check whether a newer upstream release exposes `keyboard_layout` (or the whole
`AcceptorResult`) through a dedicated API instead — if so, drop this patch and consume that.

## Add a generic hook for a server-role RDPDR (device redirection) static channel

Discussed in `ARCHITECTURE_TECHNIQUE.md` §10 ("RDP + Hello"): the RDPDR smart-card relay needs
Warpgate's `ironrdp-server`-backed viewer-facing listener to *receive* a real smart card redirected
*to* it by a connecting native RDP client — i.e. play the server role of MS-RDPEFS/MS-RDPESC.
Nothing upstream implements that role (only the client role exists, in the separate
`ironrdp-rdpdr` crate — see `warpgate-protocol-rdp/src/server/rdpdr.rs` for that from-scratch state
machine), and `ironrdp-server`'s builder has no generic hook for a custom static channel — only
hardcoded per-type factory slots (`cliprdr_factory`, sound, gfx). The underlying mechanism it uses
internally, `ironrdp-acceptor::Acceptor::attach_static_channel<T: SvcServerProcessor>`, is fully
generic but private to `ironrdp-server`'s own `client_accepted` flow.

`warpgate.patch` adds `rdpdr_factory: Option<Box<dyn RdpdrServerFactory>>` +
`.with_rdpdr_factory()` on the builder (`builder.rs`), mirroring `cliprdr_factory`'s shape exactly,
and the matching `acceptor.attach_static_channel(rdpdr)` call in `client_accepted` (`server.rs`).
`RdpdrServerFactory`/`RdpdrServer` (new file, `src/rdpdr.rs`) are a small type-erasure wrapper
around the embedder-supplied `SvcServerProcessor` — needed because `attach_static_channel` requires
a concrete type, so a bare `Box<dyn SvcServerProcessor>` alone wasn't enough; same reason
`cliprdr_factory` itself is a factory-of-a-concrete-type rather than a raw processor.

**Status as of 25 Aug 2026: builds and negotiates for real against a native RDP client, but the
larger RDPDR bridge feature this patch enables is not yet complete** — see
`ARCHITECTURE_TECHNIQUE.md` §10 for the full state (4 of 6 handshake steps confirmed, blocked on the
client never sending its capability response, diagnosis in progress). This patch's own plumbing
(the builder hook, the factory wrapper, the `attach_static_channel` call) is not implicated — traced
independently at the `ironrdp_svc`/`ironrdp_acceptor` layer and confirmed working correctly.

When re-vendoring: check whether a newer upstream release adds a generic static-channel hook (or
RDPDR support directly) — if so, drop this half of the patch and consume that instead.

## Add `ServerEvent::Rdpdr` for out-of-band RDPDR pushes

Prep for Phase 3 of the RDP + Hello smart-card bridge (`ARCHITECTURE_TECHNIQUE.md` §10, real
relay — landed after Phase 2, the target-facing client wiring). `Clipboard`/`Rdpsnd` already push
server-initiated messages through `ServerEvent` variants that call a *method* on the live,
concretely-typed processor (`self.get_svc_processor::<CliprdrServer>()`, itself an upstream
crate). RDPDR has no such upstream server-role processor to call into — ours
(`RdpdrServerChannel`, `warpgate-protocol-rdp/src/server/rdpdr.rs`) is embedder-owned and reached
through the type-erasing `RdpdrServer` wrapper (see the patch above), which only exposes the
generic `SvcProcessor` methods, not anything RDPDR-specific.

So `ServerEvent::Rdpdr(Vec<SvcMessage>)` takes pre-built messages instead of a protocol-specific
enum + a method call: the embedder (Warpgate) builds the exact `SvcMessage`s itself — it already
knows how, since Phase 1's handshake code does the same — and this arm's dispatch code only needs
the RDPDR channel id (`get_channel_id_by_type::<RdpdrServer>()`) to frame and write them. No
`get_svc_processor` call needed, unlike `Clipboard`/`Rdpsnd`.

When re-vendoring: check whether upstream ever adds real server-role RDPDR support (unlikely —
see the reasoning in the previous patch section for why the client role is the one everyone else
needs) — if so, this whole file's RDPDR-specific patches can likely be dropped in favor of it.
