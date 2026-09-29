package state

// SourceGit is the deployment source kind for a public Git repository the
// server clones itself (N2, docs/n2-contract.md section 4). SourceRef holds
// "<url>#<ref>" where <ref> may be empty; SourceDigest is sha256(url+"#"+ref).
const SourceGit = "git"
