Fork of `winrm-rs` 1.1.2.

## NTLM message encryption over HTTP never actually worked against a real WinRM server

Found and fixed 23 Aug 2026 while running `warpgate-actions`'s first live e2e
test of `windows_local_group`/`ad_domain_group` against a real domain
controller (see `ARCHITECTURE_TECHNIQUE.md` §07). Every call failed —
identically regardless of credentials, username, or domain — before any of
this crate's own logic could be blamed on a config mistake. Four real,
separate wire-format bugs, found one at a time by iterating against the live
DC (each fix changed the failure mode, not just made it disappear):

1. **The handshake sent the real SOAP body as plaintext, always.**
   `transport.rs::send_ntlm_sealed`'s no-cached-session branch called
   `NtlmAuth::handshake_and_send`, which attaches `body` unencrypted to the
   Type 3 message — regardless of `WinrmConfig::encryption`
   (`EncryptionMode::Auto` only ever controlled whether *later* calls, once a
   session was cached, sealed their body). Windows Server defaults to
   `AllowUnencrypted = false`, which makes the WinRM service reject any
   unencrypted message outright — a bare `HTTP 500`, no SOAP fault body. This
   isn't specific to one lab DC: it reproduces against any target that
   hasn't had `AllowUnencrypted` relaxed from its default, i.e. most real
   Windows targets.

2. **Sealing the body into that same Type 3 request doesn't work either** —
   confirmed empirically (`HTTP 400 Bad Request`, empty body, immediate
   `Connection: close`, all signs of an HTTP.sys-level rejection rather than
   a WinRM SOAP fault) after first trying exactly that as the fix for (1).
   `do_handshake`'s own doc comment had already flagged this ("legacy
   path... does not work with WinRM") but the crate still shipped no working
   alternative. NTLM authenticates the *connection*, not each request: the
   fix is to complete the handshake with an **empty** body first (a pure
   auth round trip), then send the real content **sealed**, as a *separate*
   follow-up request on the same keep-alive connection, without re-sending
   an `Authorization` header. `transport.rs::send_ntlm_sealed` now does
   exactly that — `handshake_and_send(..., "")` followed by
   `send_sealed_body(...)` — reusing the crate's own already-correct
   sealed-request machinery instead of adding a new one.

3. **The empty-body Type 3 request 411'd** (`HTTP.sys`: "the request must be
   chunked or have a content length") once request bodies stopped being
   silently truthy. reqwest doesn't reliably add `Content-Length: 0` for a
   genuinely empty `Vec<u8>` body the way it does for a non-empty one; Type 1
   already special-cased this with an explicit header, Type 3 didn't. Fixed
   by setting `Content-Length` explicitly for both the (now-empty) handshake
   body and, for parity/robustness, the sealed body too.

4. **The MIME framing for a sealed message has one byte-level bug in each
   direction.** `seal_body` and `unseal_body` both treated the closing
   `--Encrypted Boundary--` marker as preceded by a CRLF (`"\r\n--Encrypted
   Boundary--"`). A real capture shows the server doesn't precede its own
   closing boundary with one either — with the CRLF assumption in place, the
   outbound frame carried two extra bytes the server's parser choked on
   (`HTTP 400`, this time from the WinRM listener actually trying to decrypt
   it, not HTTP.sys front-doorring it), and inbound, `unseal_body`'s search
   for a marker that was never there fell through to treating the response's
   own closing boundary bytes as ciphertext, corrupting decryption
   (`Ntlm(InvalidMessage("checksum mismatch"))`). Fixed by dropping the
   leading `\r\n` from both marker constructions.

Verified against a real domain controller: `warpgate-actions`'s `e2e::windows`
tests (gated behind `WARPGATE_ACTIONS_WINRM_TEST` — see `connectors.rs`).
`probe_auth_and_host_role` and `ad_domain_group_grant_then_remove_round_trips`
both pass end-to-end post-patch, the latter exercising a full multi-request
`run_powershell` exchange (`CreateShell` → `Command` → `Receive` ×N →
`Signal` → `DeleteShell`, seven sealed requests in one run) — proving the
session/sequence-number continuity fix holds across a real conversation, not
just a single call. (`windows_local_group_grant_then_remove_round_trips` is
also present but fails against this specific host for an unrelated,
environmental reason — domain controllers don't have a real local SAM, so
`Add-LocalGroupMember` can't find a group `New-LocalGroup` just "created" —
not a transport bug; see that test's own doc comment.)

Check whether upstream has since fixed any of this (no issue filed for it as
of 23 Aug 2026 — file one if not, this affects every default-configured
Windows target, not just an edge case) before re-vendoring; drop this fork
once a release contains equivalent fixes for all four points above.
