# p2p end-to-end encryption — design

Status: **implemented** (2026-09-30), **revised to forced encryption**. Supersedes
the "encryption is out of scope" positioning for the *data plane*: the relay and
the hole-punched path stop being intentionally plaintext. Control frames are
unchanged.

> **Revision (forced encryption):** the original design negotiated encryption and
> fell back to plaintext for a peer that did not support it (decisions 4, 5, 7).
> That fallback is **replaced by mandatory encryption**: a session that does not
> settle encrypted is refused, never built as plaintext, and a peer that predates
> the feature is incompatible. There is no flag and no downgrade. Decisions 4, 5
> and 7 are updated in place below, and the fallback-specific wording elsewhere
> ("falls back to plaintext") is corrected to a refusal.

## Context (why)

p2p is a connectivity layer, and its data plane is plaintext by design: the DERP
relay and the KCP/hole-punched path carry smux bytes in the clear, and the docs
say confidentiality is the inner dialer's job (`tls`/`mtls`/`wss`). That holds
for a **tcp** tunnel — GOST stacks an inner dialer over the stream. It does **not**
hold for a **udp** tunnel: a datagram link (the tun case) has no inner dialer, so
IP packets cross the relay or the punched path unencrypted with nothing above p2p
to secure them. And even for a tcp tunnel, "run mtls over it" is a per-deployment
choice that silently defaults to plaintext.

The goal: encrypt the data plane end to end, so a relay (or anyone on the punched
path) can route bytes but never read them, and so a caller who forgets to add an
inner dialer is not silently exposed. This is a scoping change — the maintainer
has signed off on it; do not treat "encryption is out of scope" as a blocker for
this work.

The primitives already exist: every peer has a curve25519 identity, and control
frames are already sealed end to end with `PrivateKey.SealTo`/`OpenFrom`
(X25519 + NaCl box). The data frames are the only plaintext left.

## Decisions (settled — do not re-litigate)

1. **Scope: the whole data plane.** Every tunnel, on both transports (relay and
   direct), tcp and udp alike. Not just the udp case.
2. **Layer: the smux session's underlay.** Both transports run one `smux` session
   per peer pair; a `cryptoConn` is wrapped around that session's underlay
   (`peerConn` for the relay, the KCP conn for direct) and `smux` runs over the
   ciphertext stream. One choke point, tcp/udp handled identically.
3. **Key agreement: an ephemeral X25519 per (peer, transport), HKDF → AEAD.** The
   ephemeral is generated once and kept for the pair+transport's lifetime
   (destroyed at process end), *not* per smux session — see the lifetime note
   below. It is still ephemeral, so forward secrecy holds against a later
   static-key compromise. No new dependency the module does not already have.
4. **Forced, not negotiated.** A peer that supports it proves it by sending a
   handshake frame; a peer that does not (an older version, or a relay that drops
   the frame) never settles, and the session is **refused** — no plaintext session
   is built. A mixed-version pair is incompatible; there is no fallback.
5. **Always on, no flag.** Encryption is the only mode, not a default that can be
   turned off. Both ends must support it; a pair that does not settle is refused
   (decisions 4 and 7).
6. **Independent transports.** Relay and direct have separate secure sessions
   (separate ephemerals, keys and counters), so their nonce spaces never touch.
   Cost: the relay session's first-ever bring-up pays one control round trip.
7. **No downgrade.** Because encryption is forced, an on-path relay that *drops*
   the handshake frames cannot force plaintext — it can only prevent the session
   (a denial of service, not a confidentiality break). The old "surfaced, not
   prevented" caveat no longer applies; the refusal is reported as
   `p2p.ErrEncryptionRequired` (`codes.FailedPrecondition` over gRPC).

## Design

### Session-layer cipher (`internal/host/secure.go`)

A `cryptoConn` implements `net.Conn` over an underlay conn, transforming a byte
stream to a stream of AEAD records. It is a **passive** wrapper: it is handed a
finished key set and does no handshake I/O of its own (the handshake runs over the
control channel, which is not this underlay).

- Two keys per session, one per direction, derived from the handshake. Each
  direction has its own 12-byte nonce = a 4-byte zero prefix followed by an
  implicit 8-byte counter starting at zero. The prefix is a constant, not a random
  per-key value: the handshake derives a fresh key per session, so a counter that
  starts at zero can never repeat a `(key, nonce)` pair, and a random prefix would
  only cost bytes without adding safety.
- Record = `[4B big-endian length][ciphertext + 16B tag]`. `Write` splits into
  records of at most 16 KiB of plaintext; `Read` accumulates a whole record before
  decrypting and buffers the plaintext for partial reads.
- chacha20poly1305 (`golang.org/x/crypto/chacha20poly1305`, already a transitive
  dependency via `nacl/box`).
- **The counter is implicit and never transmitted.** Both underlays are reliable
  and ordered (DERP is a WebSocket over TCP; KCP is a retransmitting ARQ), so a
  record can never be reordered or lost at this layer. A record that fails to
  authenticate is fatal: the session is torn down (the peer redials).
- `SetReadDeadline`/`SetWriteDeadline`/`Close` delegate to the underlay, matching
  the existing conn wrappers' expectations.

### Why a new control frame, not `ctrlCaps`

Negotiation and key material travel in **one** sealed frame: receiving it proves
the peer supports encryption *and* delivers its ephemeral key, so there is no
"supported but no key" intermediate state. The only question is whether that frame
is a new kind or the existing `ctrlCaps` (0x04). It is a new kind (0x05):

- **`ctrlCaps` is a capability bitfield with the wrong contract.** Its payload is
  1 byte; its documented semantics are "I *understand* this capability", freely
  re-broadcast, and the receiver **OR-merges** the bits (`addCaps` does
  `peerCaps |= bits`). A 32-byte per-session ephemeral public key must not be
  OR-merged or treated as idempotent, and every session's is different.
- **`ctrlCaps` is punch-scoped, and its receiver is `directConn`.** It is only
  sent inside the punch, and lands in the *direct path's* `directConn.peerCaps`;
  the relay session, which also needs a handshake, has no `directConn` to land in.
  Reusing it would mean sending caps on the relay path too, adding a transport
  tag, making the frame variable-length, and special-casing its merge — at which
  point "reuse" is a rename and 0x04's contract is broken.
- **A new kind costs no compatibility.** `handleControl` is a switch with no
  `default`, so an unknown kind is skipped; an old peer drops 0x05, sends none,
  and the session is refused (it does not settle). A new frame is no harder to
  interop than an extended one.

The alternative with *zero* new frames is static-static ECDH over a `capsEncrypted`
bit — but that forfeits forward secrecy, which was the rejected option. Forward
secrecy requires shipping an ephemeral key, and 0x04 cannot carry it.

### Session lifetime and rebuilds

The secure session is scoped to **(peer, transport)** and lives on the engine,
**not** on the smux session it protects. This is forced by the engine's
lifecycle: a `peerConn` (relay) may be killed and rebuilt on *one* side alone —
`TestInboundRecoversAfterAdapterClosed` simulates exactly this (a queue overflow,
or a peer restart the other end was not told about) — while the other side keeps
its live smux session. Under plaintext that is transparent. Under a *per-session*
key it is fatal: the rebuilding side would derive a fresh key while the other end
still holds the old one, and every record would fail authentication.

So the key material and the nonce counters are **cached per (peer, transport) and
outlive the smux session**:

- A one-sided rebuild reuses the same ephemeral, key and counter → transparent
  recovery, exactly as plaintext.
- **The nonce counters are shared** (per pair+transport+direction) and passed by
  pointer into each `cryptoConn`, so a rebuilt session continues the sequence
  instead of restarting at zero. Two `cryptoConn`s over the pair's life share one
  counter — a session may therefore build its cipher more than once.
- The transport is folded into the HKDF `info`, so relay and direct derive
  *different* keys from the same ephemerals and each has its own counters; their
  nonce spaces never touch.
- **A peer restart changes its ephemeral.** On receiving a half that differs from
  the one already settled, the receiver re-derives, **resets the counters** (a new
  key opens a fresh nonce space) and tears down the peer's smux session so it is
  rebuilt over the new cipher. Both ends converge in one exchange. A half that is
  *unchanged* is a no-op (the resend guard below).

Forward secrecy: the ephemeral private key is destroyed when the session is
dropped (process end), so a later compromise of a peer's *static* key does not
reveal past traffic. It is not rotated per smux session — the cost of the
rebuild-safety above.

### Handshake

Runs once per (peer, transport), over the relay control channel (sealed control frames via
DERP `SendPacket`). The control channel is usable exactly when the relay session
can exist, and the direct punch already depends on it, so it is always available
when a session is being built; the direct session may outlive a relay teardown,
but its handshake completes while the relay is still up.

- New control kind **`ctrlSecure = 0x05`**. Payload (inside the existing static
  `SealTo` seal) = `[transport 1B][ephPub 32B][want 1B]`, where `transport` is
  `0x00` for the relay session and `0x01` for the direct session. `want` is set
  while the sender is unsettled: it asks the peer to (re-)send its half, which is
  how a lost reply heals. The seal is what makes the exchange authenticated: only
  the holder of the peer's static private key can produce a valid frame, so the
  relay can route the half but cannot forge it.
- On receipt, the peer opens the box, learns the ephemeral public key, and sends
  **its own** half when the sender is asking (`want`), when it is itself
  unsettled, or when the sender's ephemeral changed. A settled peer that is not
  asked stays quiet, so the exchange terminates.
- Each side computes `ss = X25519(ownEphPriv, peerEphPub)` and
  `keys = HKDF-SHA256(ss, salt = sort(ephA || ephB), info = "p2p-session-v1" || transport)`,
  split into the two directional keys.
- **No explicit session id is needed.** The ephemerals are fresh per session and
  the salt contains both, so the derived keys are unique; the `transport` byte
  keeps the relay and direct handshakes from colliding. The ephemeral private key
  is retained for the (peer, transport) session's life, so a peer restart (a new
  peer ephemeral) can be re-derived with it.

**Triggering (breaks a one-sided deadlock):** a host sends its half when *either*
(a) it is bringing up a session it needs, or (b) it received the peer's half. Rule
(b) matters because `pump` routes a control frame to `handleControl` without
creating a `peerConn` — so on a one-sided tunnel the answering side would never
send its half if it only reacted to session bring-up, and the opening side would
wait forever (it cannot send smux data until the key exists, so it cannot trigger
the peer with data). Receiving a `ctrlSecure` therefore also makes the receiver
ensure a `peerConn` for that peer and send its own half.

**Loss handling:** a half is sent on bring-up, re-sent whenever the peer's half
arrives while we are unsettled or the peer asks, and re-sent on an interval until
the handshake deadline while we are still unsettled. A lost half or reply
therefore self-heals within one interval: the `want` bit makes the settled peer
answer a retry even though the half it already holds is unchanged. No resend timer
is needed past the bring-up deadline — the DERP control channel is a WebSocket
over TCP, so transport loss does not occur; the only way both halves are dropped
is a relay dropping them deliberately, which is the refusal case below.

### Negotiation and refusal (no fallback)

Support is proven by receipt: a session is encrypted **iff** the peer's `ctrlSecure`
for that transport arrived before the bring-up deadline; otherwise the session is
**refused** — no underlay is wrapped and no plaintext session is built.

- Old peers: `handleControl`'s switch has no `default`, so an unknown kind is
  dropped silently. An old peer ignores `ctrlSecure` and never sends one → we time
  out → the session is refused. A mixed-version pair is therefore incompatible (no
  caps bit is needed for this feature: the frame *is* the advertisement and the key
  material).
- A session's first data packet may arrive before the handshake settles. The
  bring-up **waits a bounded time** for the handshake and, on timeout, refuses the
  session — no unbounded buffering of pre-handshake data, and never a plaintext
  send.
- The inbound/pump path is **non-blocking**: it does not wait on a relay round
  trip, so it builds the cipher only if the session is already settled; an
  unsettled packet on that path is dropped rather than stalling the pump
  (`errEncryptionRequired`).

**A dropped handshake is a denial of service, not a downgrade:** an on-path relay
that *drops* both directions' `ctrlSecure` frames cannot force plaintext — it can
only keep the session from settling, so the tunnel never comes up. There is no
confidentiality loss to surface; the refusal is reported as
`p2p.ErrEncryptionRequired` (`codes.FailedPrecondition` over gRPC).

### Integration points

| Where | Change |
|---|---|
| `internal/host/secure.go` (new) | `cryptoConn`, key derivation, the per-session secure state (booleans `started`/`ready` — an unsettled session is refused, `errEncryptionRequired`; it becomes `ready` once both halves are present and the keys derive). |
| `internal/host/engine.go` `sessionLocked` (~969) | ensure the secure state is `ready`, then `smux.Client(&cryptoConn{pc}, cfg)` instead of `smux.Client(pc, cfg)`. The handshake wait runs **outside `pc.mu`**, following the existing `maybeStartDirect` release-then-start pattern (see the lock-inversion note at engine.go:905). |
| `internal/host/engine.go` `handleControl` (~662) | `case ctrlSecure`: open the box, drive the state machine, ensure the `peerConn` and our own half (rule (b) above). |
| `internal/host/direct.go` punch (~660) | send the direct half alongside `sendCaps`/`sendCandidates`; await the peer's half before building the direct smux session; wrap the KCP conn (~770). |
| `internal/host/direct.go` kinds (~45) | add `ctrlSecure = 0x05`. |

`peerConn` gains a `secure` field; `directConn` gains an equivalent. Both refuse to
build the cipher before `ready`, so smux never runs over a plaintext underlay.

### Observability

- `Status`: aggregate gauges `encrypted_peers` / `plaintext_peers` (the proto
  change lands in `plugin/p2p/proto` and bumps that module), plus a per-peer
  in-process map shaped like `PeerTransports` but keyed by base64 peer key, whose
  value is `secure` or `plaintext`. With encryption forced, `encrypted_peers`
  counts every connected (always-encrypted) peer and `plaintext_peers` is a
  **constant 0**; a refused peer has no data path and is not reported at all. The
  fields are retained for API/wire stability; the `plaintext` map value is kept
  for compatibility and never produced for a live peer.
- One log line per session build: `session up peer=… transport=… secure=true|false`
  (always `true` for a live session); a refusal is logged separately at `warn`.

Release note: the two aggregate gauges require new fields
(`encrypted_peers`/`plaintext_peers`) on `StatusReply` in `plugin/p2p/proto`, so
the `p2p` module's **standalone build (`GOWORK=off go build ./...`) is red**
until the `plugin` module is tagged and `p2p`'s requirement is bumped to that tag
— the workspace build, which resolves `plugin` through `go.work`, is green in the
meantime. The per-peer map is in-process only, like `PeerTransports`: the gRPC
transport carries the two aggregate gauges and nothing per-peer.

## Security properties

- **Confidentiality/integrity/authenticity** of the data plane against the relay
  and any on-path observer: they see ciphertext and framing (packet sizes, timing)
  but cannot read or forge bytes.
- **Authentication** rests on the existing static curve25519 identities; the
  handshake is sealed to the peer's static key, so a malicious relay cannot MITM.
- **Forward secrecy per session**: the ephemerals are ephemeral and discarded.
- **No downgrade**: encryption is forced, so a relay that drops the handshake can
  only prevent the session (a denial of service), never force plaintext — the data
  plane cannot be silently downgraded by an on-path relay.
- **Not addressed (by design):** traffic analysis / size or timing correlation
  (padding is out of scope); replay across sessions (a fresh ephemeral makes replay
  useless, and there is no session-id echo to exploit); rekeying within a session
  (sessions are short-lived and rebuilt with new keys).

## Verification

- **Unit:** `cryptoConn` round-trip, tamper detection (a flipped byte fails
  authentication and kills the session), counter advance, and partial reads; the
  handshake state machine (peer-supported, timeout→refusal, resend, one-sided
  rule (b)); HKDF/key-separation determinism.
- **e2e** (nested netns + real derper, per the existing harness): a tunnel comes up
  encrypted and curl succeeds; `--direct=false` (relay-only) is also encrypted; a
  packet capture on the relay shows the `0x01` payload is **not** plaintext; a
  mixed old/new pair is refused (the session never comes up), not carried in the
  clear.
- Run tests with `-race` and `CGO_ENABLED=1` per the repo standard.

## Non-goals

- Traffic-analysis resistance (padding, constant-rate).
- In-session rekey.
- Changing the control channel (it stays statically sealed).
- A `requireEncryption` flag. Forced encryption (no fallback) is now the
  behavior, so no flag is needed: a session that does not settle is refused.
