# Open Card RC license manifest

The M7 release bundle carries this directory unchanged and records its
checksums in `licenses-manifest.json`. It is a source notice, not a grant of
rights beyond the licenses of the individual components.

The Open Card source is released under the repository license. Go modules,
frontend packages, Debian inputs, and pinned runtime assets retain their
upstream licenses. The canonical bundle must include an explicit notice or a
`NOASSERTION` entry for every copied dependency; an absent notice is a release
failure.

The M7 assembler never downloads license text, contacts a registry, or infers
license terms from a package name. Supply-chain evidence is generated from the
checked-in source, the fixed asset manifest, and the explicit Debian input
manifest.
