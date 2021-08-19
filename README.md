# pacman-bintrans

This is an experimental implementation of binary transparency for pacman, the
Arch Linux package manager. This project builds on [prior work][1] by Mozilla.

[1]: https://wiki.mozilla.org/Security/Binary_Transparency

Cryptographic signatures prove that a message originates from somebody with
control over the private key, but it's impossible to prove that the private key
didn't sign additional messages. In update security this means that you can't
be confident the update you receive is the same one everybody else has received
with signed updates alone. Somebody in control of the update key might craft a
malicious update, sign it and feed it specifically to you. This attack is much
less likely to get noticed than pushing a malicious update to all users.

The mozilla/pacman-bintrans approach to binary transparency piggybacks on
transparency infrastructure for x509 certificates. The database file is only
considered valid if a certificate has been issued for the checksum of the
database on a configured domain. The database in turn contains the checksums of
all the packages, acting as a very simple merkle-tree. The certificate is
expected to have multiple embedded SCTs from transparency logs. An SCT is a
signed timestamp that confirms that a given transparency log has seen the
certificate and promises to include it in its log. As long as at least one
transparency log is not colluding the existence of the database is going to be
logged.

# Usage

pacman-bintrans integrates into pacman by registering it as a custom transport
in `/etc/pacman.conf`:

    XferCommand = /usr/bin/pacman-bintrans -O %o %u

By default, no rules are enforced and pacman should just work as usual. Verify
this by running `pacman -Suyy`.

# Configuration

    TODO

# Generating transparency proofs

This section is intended for package maintainers that are planning to run
package repositories with binary transparency enabled.

    TODO

# License

GPLv3+
