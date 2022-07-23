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

pacman-bintrans integrates into pacman by registering it as a custom transport
in `/etc/pacman.conf`:

    XferCommand = /usr/bin/pacman-bintrans -O %o %u --transparency-url https://pacman-bintrans.vulns.xyz/sigs/ --pubkey 'RWSC6c8TVaOYGoe60E+sPiPgumSQENiSNJrBOH6IUYdfmY9xIDJCFXa2'

To verify everything is working correctly you can clear your download cache
with `pacman -Scc` and then try to re-download and reinstall a package with
`pacman -Suy filesystem`.

pacman still verifies pgp signatures, but in addition also runs `rekor-cli
verify` on each package to ensure it has been properly logged in the sigstore
transparency log.

# Verifying Reproducible Builds

Arch Linux has multiple [independent
rebuilders](https://github.com/kpcyrd/rebuilderd). A rebuilder tracks all
pre-compiled packages in Arch Linux, downloads the source code and attempts to
compile them again and expects the resulting package to be bit-for-bit
identical with the official, pre-compiled package. Arch Linux supports this by
publishing [BUILDINFO](https://archlinux.org/pacman/BUILDINFO.5.html) files
that describe the build environment. A rebuilder can use this file to setup an
almost identical build environment that matches all compiler and library
versions of the original build environment. At the time of writing this works
with about 86% of all packages in Arch Linux. Software shouldn't attempt to
track anything of the build environment that can't reasonably be normalized,
for example by probing the current date/time or by testing for cpu features
like SSE/AVX at build time instead of runtime.

To query a rebuilder for every update you're about to install you can add
`--rebuilder <url>`, this option can be set multiple times:

    --rebuilder https://reproducible.archlinux.org/
    --rebuilder https://r-b.engineering.nyu.edu/
    --rebuilder https://wolfpit.net/rebuild/

The full command could look like this:

    XferCommand = /usr/bin/pacman-bintrans -O %o %u --transparency-url https://pacman-bintrans.vulns.xyz/sigs/ --pubkey 'RWSC6c8TVaOYGoe60E+sPiPgumSQENiSNJrBOH6IUYdfmY9xIDJCFXa2' --rebuilder https://reproducible.archlinux.org/ --rebuilder https://r-b.engineering.nyu.edu/ --rebuilder https://wolfpit.net/rebuild/

To configure a threshold of required successful builds for every update you can
use this option:

    --required-rebuild-confirms 2

🚧 **But wait!** 🚧 Rejecting all packages that haven't been reproduced by at
least two other parties is a really exciting goal with massive security
benefits, unfortunately there are still too many unreproducible packages and
nobody has managed to build a useful system with _only reproducible software_
**yet**. If you use `--required-rebuild-confirms` with anything higher than `0`
your update system is eventually going to stop working because pacman can't
download any unreproducible updates anymore (this may even include critical
security updates).

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

It's possible to make all requests through a proxy (eg. Tor) with the `--proxy
<value>` flag for privacy reasons. This includes the package download, the
connection to the `--transparency-url`, the connection to the transparency log
and the connections to any rebuilders.

    XferCommand = /usr/bin/pacman-bintrans --proxy 'socks5h://127.0.0.1:9050' --bypass-proxy-for-pkgs -O %o %u --transparency-url https://pacman-bintrans.vulns.xyz/sigs/ --pubkey 'RWSC6c8TVaOYGoe60E+sPiPgumSQENiSNJrBOH6IUYdfmY9xIDJCFXa2'

To speed up upgrades you can use `--bypass-proxy-for-pkgs` so the packages are
downloaded directly, but the extra security checks run through the proxy.

## Acknowledgments

Current development is crowd-funded through [GitHub sponsors](https://github.com/sponsors/kpcyrd).

Initial development in 2021 was funded by Google and The Linux Foundation.

# License

GPLv3+
