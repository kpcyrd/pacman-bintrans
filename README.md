# pacman-bintrans

This is an **experimental** implementation of binary transparency for pacman,
the Arch Linux package manager. This project was originally heavily inspired by
[prior work][1] by Mozilla and then re-implemented with the rekor transparency
log of [sigstore][2].

[1]: https://wiki.mozilla.org/Security/Binary_Transparency
[2]: https://www.sigstore.dev/how-it-works

Cryptographic signatures prove that a message originates from somebody with
control over the private key, but it's impossible to prove that the private key
didn't sign additional messages. In update security this means a signed update
is a strong indicator the update is authentic, but you can't be sure this
update is the same update everybody else got. Somebody in control of the update
key could craft a malicious update, sign it and feed it specifically to you.
This attack is much less likely to get noticed than pushing a malicious update
to all users.

Because transparency logs work best with a "single-purpose key", meaning the
key is only ever used to sign Arch Linux packages, we're creating a special
"transparency key". The operator needs to sign every Arch Linux package and
upload the signature to the transparency log. They also need to maintain an
audit log that tracks why each signature was created.

An external auditor could then fetch all signatures from sigstore and check if
they belong to officially released packages.

# Usage

**Note: there's no public deployment yet, this is more of a developer preview.**

pacman-bintrans integrates into pacman by registering it as a custom transport
in `/etc/pacman.conf`:

    XferCommand = /usr/bin/pacman-bintrans -vO %o %u --transparency-url https://pacman-bintrans.vulns.xyz/sigs/ --pubkey 'RWSC6c8TVaOYGoe60E+sPiPgumSQENiSNJrBOH6IUYdfmY9xIDJCFXa2'

To verify everything is working correctly you can clear your download cache
with `pacman -Scc` and then try to re-download and reinstall a package with
`pacman -Suy filesystem`.

pacman still verifies pgp signatures, but in addition also runs `rekor-cli
verify` on each package to ensure it has been properly logged in the sigstore
transparency log.

# Configuration

    TODO

# Generating transparency proofs

This section is intended for package maintainers that are planning to run
package repositories with binary transparency enabled.

    cd pacman-bintrans-sign
    cargo run --release -- -v \
        --repo-url 'https://ftp.halifax.rwth-aachen.de/archlinux/$repo/os/$arch' --repo-name core --architecture x86_64 \
        --signature-dir ../www/ --pubkey-path ~/keys/minisign.pub --seckey-path ~/keys/seckey

## Searching the transparency log

There's a command to list all signatures that have been logged so far:

    cd pacman-bintrans-monitor
    cargo run

## Fetching with a proxy

Note this doesn't fully torify all traffic, it only uses it to download the
package and fetch from `--transparency-url`:

    cargo run -- -vvO filesystem-2021.05.31-1-x86_64.pkg.tar.zst https://ftp.halifax.rwth-aachen.de/archlinux/core/os/x86_64/filesystem-2021.05.31-1-x86_64.pkg.tar.zst \
        --pubkey 'RWSC6c8TVaOYGoe60E+sPiPgumSQENiSNJrBOH6IUYdfmY9xIDJCFXa2' --transparency-url 'http://2iz5fzvuwjapcv5v2msvhlr5oqbwriznwu7hnsccrsho47ljqynrgryd.onion/sigs/' \
        --proxy 'socks5h://127.0.0.1:9050' --bypass-proxy-for-pkgs

# License

GPLv3+
