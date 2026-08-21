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
