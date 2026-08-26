# Sample provenance

Every file here is a **real payload captured from a live endpoint**, recorded so a reader can tell
what is evidence and what is not. Captured **2026-08-26 UTC**.

> The rule is `tests/PatchManagement.Content.Tests/Samples/PROVENANCE.md`'s, and it applies
> unchanged: **do not add a hand-authored fixture here.** A classifier asserted against a banner
> written to that classifier proves self-consistency and nothing else. If a shape cannot be
> captured, the behaviour stays untested and its criterion stays unticked.

## SSH banners — `banners/<container>.banner.txt`

The first bytes each lab container's `sshd` sends on connect, unedited, **including the trailing
CRLF** (RFC 4253 §4.2 terminates the identification string with CR LF, and a classifier that only
works after someone has trimmed it is not the thing being tested).

Captured by connecting a raw TCP socket to `127.0.0.1:<published port>` and reading once. No SSH
client, no key exchange — the banner is sent unsolicited before any negotiation, which is exactly
why it is usable for classification *before* a connector is chosen.

| File | Bytes | Banner | What it establishes |
|---|---|---|---|
| `ubuntu2204.banner.txt` | 42 | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.16` | Distro named outright — Ubuntu, Debian family |
| `ubuntu2404.banner.txt` | 43 | `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18` | Same, different OpenSSH and package revision, so the parse cannot key on version text |
| `debian12.banner.txt` | 41 | `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10` | Debian named outright; the suffix shape (`2+deb12u10`) differs from Ubuntu's |
| `rocky9.banner.txt` | 21 | `SSH-2.0-OpenSSH_9.9` | **Says nothing about the distro** |
| `alma9.banner.txt` | 21 | `SSH-2.0-OpenSSH_9.9` | **Byte-identical to Rocky's** |

### The finding these captures exist to record

**Rocky 9 and AlmaLinux 9 produce byte-identical banners**, and neither names a distro, a family, or
anything beyond an OpenSSH version. This was not assumed — it was observed, and it is the reason
the classifier reports `unknown` for them rather than guessing `rhel`.

That matters more than it first appears. The tempting implementation infers "no vendor suffix ⇒
Red Hat family", because on this fleet that happens to be true. It is **not** true in general —
upstream OpenSSH, Alpine, and any distro that does not patch the version string all produce a bare
banner — so a classifier keying on absence would be right for the lab and wrong in the field, with a
green test suite either way.

The two identical files are kept **both**, deliberately. A single one would let a reader assume the
value is distro-specific and merely unrecognised; two different distros emitting the same bytes is
the evidence that the banner carries no distro information at all.

**Consequence for criterion (b), recorded in `docs/phases/phase-4.md`:** banner classification
closes the Debian family and is honestly indeterminate for the RHEL family. Establishing that a bare
banner is Rocky rather than Alma requires reading `/etc/os-release`, which requires a login — which
is inventory, not classification.
