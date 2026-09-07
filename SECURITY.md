# Security

Lightning in a Jar holds real funds. If you find a way to lose them, read them, or make the wallet do something its owner did not ask for, please tell us privately first.

## How to report

- **Preferred:** GitHub private vulnerability reporting — the *Security* tab of this repository → *Report a vulnerability*. It reaches the maintainer only and gives the report a private thread.
- **Or e-mail:** dp@modulo.network — say "LiJ security" in the subject. If you want to encrypt, ask for a key in a first message.

Please do not open a public issue for anything that could be exploited before it is fixed.

## What to expect

- An acknowledgement within 4 days.
- We will tell you what we found, what we changed, and when it shipped (every wallet build has a version string; the fix will name it).
- Credit in the release note if you want it; silence if you prefer.
- This is a one-developer project with no bug bounty. What we can offer is a fast, honest fix and your name on it.

## Scope

In scope: this repository (the engine, the page, the build), the LIJOX registry worker ([dav1dpgit/LIJOX](https://github.com/dav1dpgit/LIJOX)), the LSP adapter ([dav1dpgit/lijox-lnd-adapter](https://github.com/dav1dpgit/lijox-lnd-adapter)), and the live deployment at lightninginajar.xyz.

Out of scope: denial of service against the author's own LSP nodes and the registry (they are one operator's boxes; please do not knock them over to prove they can be knocked over), and findings that need the user's own seed words.

## Where the sharp edges are

Read before you look: the `lightning` crate is LDK 0.0.123 plus a small patch set — every changed line is in [docs/ldk-patches.md](docs/ldk-patches.md). The page's Content-Security-Policy is strict (script by hash only), so an injection finding should show the payload actually running. The wallet's state backup is sealed under a seed-derived key before it leaves the device; the interesting question there is what the holder can learn from size and timing, not from contents.
