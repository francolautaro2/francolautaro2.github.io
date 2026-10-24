---
layout: post
title: "Bringing a dead multiplayer back: rebuilding the Uncharted 2 server in Go"
date: 2026-10-24 12:00:00 -0300
categories: [reverse-engineering, security]
tags: [uncharted-2, ps3, go, protocols, cryptography, wireshark, networking]
---

In 2019 Sony shut down the multiplayer servers for Uncharted 2 on PS3. The game still boots, the menus still load, but the moment you press "Multiplayer" the client reaches out to infrastructure that no longer exists.

So I decided to rebuild the server side from scratch, in Go, using nothing but the original client and the traffic it produces. This post is about *how* you do that: how you turn a black box that talks over the network into a protocol you understand well enough to answer.

## Ground rules first

Before any packet capture, a few rules I set for the project:

- **No Sony code, binaries or assets are distributed.** The server is written from scratch. It only speaks the same language as the client.
- **Interoperability and preservation, not piracy.** The game must be legitimately owned; the server only restores a feature that was switched off.
- **Non-commercial.** Nobody pays to play.
- **The code and tooling stay private.** Publishing a ready-made toolkit is a different thing from writing about the methodology.

Reverse engineering for interoperability is a legitimate discipline, but it's one where you should decide your boundaries *before* you start, not after.

## Step 1: the client is the specification

There is no documentation. The only source of truth is the client, so the first phase is pure observation.

I captured traffic with **Wireshark** while exercising every flow I could: booting into multiplayer, logging in, browsing lobbies, joining matches, failing to connect. The goal at this stage isn't to understand anything — it's to collect enough samples that patterns start to emerge:

- Which hosts and ports does the client try to reach, and in what order?
- What does it send *first*? (The first message usually tells you who's expected to speak and what a "hello" looks like.)
- What does it do when it gets no answer, or garbage? Timeouts and retry behaviour reveal what the client considers a valid reply.

A useful mindset: every byte the client sends is a question, and every hang or disconnect is the client telling you your answer was wrong.

## Step 2: transport and framing

The traffic runs over **TCP**, which immediately raises the most common beginner mistake in protocol work: TCP is a *stream*, not a sequence of messages. One `Read()` can return half a message or three messages glued together.

So before parsing anything, you need to discover the framing: how does the receiver know where one message ends and the next begins? Usually it's a fixed-size header containing a length field. Once you find it, everything gets easier — you can split a capture into discrete messages and start comparing them side by side.

```go
// Simplified: read one length-prefixed frame from a TCP stream.
func readFrame(r io.Reader, maxSize uint32) ([]byte, error) {
    var hdr [4]byte
    if _, err := io.ReadFull(r, hdr[:]); err != nil {
        return nil, err
    }
    n := binary.BigEndian.Uint32(hdr[:])
    if n > maxSize {
        return nil, fmt.Errorf("frame too large: %d", n)
    }
    buf := make([]byte, n)
    _, err := io.ReadFull(r, buf)
    return buf, err
}
```

Note the `maxSize` check. A server that allocates whatever length the peer claims is a server that can be knocked over with a single packet. More on that later.

## Step 3: decoding a binary protocol (TLV)

With messages separated, the payloads turned out to follow a **TLV** (Type–Length–Value) structure: each field starts with a type tag, then the length of its value, then the value itself. Fields can nest, so a value can itself be a list of TLV fields.

TLV is a great format to reverse engineer because it's *self-describing* enough that you can parse a message you don't understand yet. You can walk the whole tree, print every field, and only later figure out that type `0x0004` is a user ID and type `0x000B` is a timestamp.

The technique that worked best for me was **differential analysis**:

1. Capture the same action twice with one variable changed (a different account, a different lobby, a few seconds later).
2. Diff the decoded trees.
3. The fields that changed are the ones tied to that variable.

Timestamps reveal themselves because they grow monotonically. IDs reveal themselves because they repeat across unrelated messages. Lengths reveal themselves because they always match the size of something nearby.

A generic TLV walker in Go looks something like this:

```go
// Simplified TLV walker: 2-byte type, 2-byte length, then value.
type Field struct {
    Type  uint16
    Value []byte
}

func parseTLV(b []byte) ([]Field, error) {
    var out []Field
    for len(b) > 0 {
        if len(b) < 4 {
            return nil, errors.New("truncated header")
        }
        t := binary.BigEndian.Uint16(b[0:2])
        l := int(binary.BigEndian.Uint16(b[2:4]))
        b = b[4:]
        if l > len(b) {
            return nil, fmt.Errorf("field 0x%04x claims %d bytes, only %d left", t, l, len(b))
        }
        out = append(out, Field{Type: t, Value: b[:l]})
        b = b[l:]
    }
    return out, nil
}
```

*(Field widths and endianness here are illustrative — the point is the shape of the parser, not the exact layout.)*

## Step 4: identity, tickets and ECDSA

The most interesting part of the protocol, and the one closest to real security engineering, is authentication.

On the PS3, games don't authenticate users themselves. The console obtains an **NP ticket** — a signed binary blob that says, roughly, *"this is user X, issued at time T, valid until T', for service S"* — and the game hands that ticket to its own servers. The game server's job is not to check a password; it's to check the ticket.

That check boils down to three questions:

1. **Is the signature valid?** The ticket carries an **ECDSA** signature over its contents. The server verifies it against the issuer's public key. If a single byte of the ticket was altered, verification fails.
2. **Is it still valid?** Check the issue and expiry timestamps. A perfectly signed ticket from last week should still be rejected.
3. **Is it for me?** A ticket issued for another service shouldn't be accepted by this one.

```go
// Simplified: verify the signature over the signed portion of a ticket.
func verifyTicket(pub *ecdsa.PublicKey, signed, sig []byte, now time.Time, t Ticket) error {
    digest := sha256.Sum256(signed) // hash choice depends on the ticket format
    if !ecdsa.VerifyASN1(pub, digest[:], sig) {
        return errors.New("bad ticket signature")
    }
    if now.Before(t.IssuedAt) || now.After(t.ExpiresAt) {
        return errors.New("ticket outside validity window")
    }
    if t.ServiceID != expectedServiceID {
        return errors.New("ticket issued for another service")
    }
    return nil
}
```

What makes this a good lesson in applied cryptography is that the hard question isn't the math — Go's `crypto/ecdsa` does the math. The hard question is **trust**: *whose* public key are you verifying against? In a private-server ecosystem, the original issuer is gone, so you have to decide who issues tickets now, how that key is protected, and what your server accepts. Getting the signature check right but trusting the wrong key is the same as having no check at all.

## Step 5: emulating a backend that isn't there

Not everything on the other side of the wire was a simple request/response server. Part of the original backend behaved like a **message broker**, with **AMQP/RabbitMQ**-style semantics: queues, exchanges, routing, acknowledgements.

That changes the job. You're no longer answering a request; you're impersonating a piece of infrastructure, and the client expects its *behaviour*, not just its message formats:

- Messages must be delivered in the order the client expects.
- Acknowledgements must arrive when the client is waiting for them, not before and not after.
- State (which queues exist, who's subscribed to what) has to be consistent across connections.

This is where Go shines. Goroutines and channels map very naturally onto "one connection, one goroutine, messages routed through channels", and the race detector catches the concurrency bugs you will inevitably write while emulating a broker.

## The security lessons

Writing a server for a client you don't control is a crash course in defensive programming, because your server is now internet-facing and every input is attacker-controlled:

- **Never trust a length field.** Every length read from the wire is bounds-checked before it's used to slice or allocate. This one rule prevents an entire class of crashes and memory exhaustion attacks.
- **Parsers are the attack surface.** A TLV parser that recurses into nested fields needs a depth limit. A parser that panics on malformed input is a denial-of-service waiting to happen. Fuzzing the decoders (Go has native fuzzing since 1.18) is cheap and finds real bugs.
- **Validate time and context, not just signatures.** Expiry windows and service binding are what stop replayed tickets.
- **Fail closed.** If something doesn't parse or doesn't verify, the connection dies. No "best effort" authentication.

## What it taught me

This project started from nostalgia, but it ended up being the most complete systems education I've had outside of work: binary protocol analysis, TCP stream handling, applied cryptography, message-broker semantics, concurrency, and adversarial input handling — all in one codebase, all with a client that gives you zero help.

The biggest lesson is methodological: **reverse engineering is mostly patience and bookkeeping.** Capture, diff, hypothesise, implement, watch the client either accept your answer or reject it, repeat. The breakthroughs are rarely clever; they're the result of having enough well-labelled samples that the pattern becomes obvious.

And there's something hard to beat about pressing "Multiplayer" on a game that was declared dead, and watching it connect.
