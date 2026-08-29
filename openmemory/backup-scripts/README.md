# OpenMemory offline operations

These scripts replace the former live export path with a bounded, writer-free
maintenance job. They do not call the memory API or create Qdrant snapshots.

## Commands

```bash
./backup-scripts/selfcheck_openmemory_ops.sh
./backup-scripts/health_openmemory.sh
./backup-scripts/backup_openmemory.sh
./backup-scripts/install_launchagents.sh
```

The scheduled backup admits throughout the `00:05` local-time minute to tolerate
LaunchAgent startup jitter and reserves the `00:05-00:15` maintenance window. A token-backed one-shot run requires `--one-shot`,
`OPENMEMORY_ONE_SHOT_TOKEN_FILE`, and its owner-only
`OPENMEMORY_ONE_SHOT_TOKEN_SHA256`; it bypasses the calendar-minute gate and
uses a bounded 10-minute deadline by default. The token is never logged or
passed as an argument. Retention keeps the two newest authenticated,
restore-verified local backups and never prunes Drive, production volumes, or
an ambiguous candidate.

## Backup contract

The coordinator records an owner-only lock, journal, state, restart policies,
container/image/volume identity, a pinned `git` HEAD plus the complete P0
overlay source snapshot, an SQLite online-backup snapshot read from the
`openmemory_openmemory_db` Docker named volume, and metadata-preserving
archives of `openmemory_mem0_history` and `mem0_storage`. It stops all three
Compose services, verifies the writer barrier, runs SQLite integrity checks,
and runs `restore_openmemory_clone.sh` on an isolated network with a separate
`DATABASE_URL=sqlite:////clone-data/openmemory.db`.

The protected root receives only authenticated GPG ciphertext and one minimal
non-secret pointer; detailed manifests, state and checksums remain local-only.
Encryption uses the approved AEAD command and retrieves the
passphrase from macOS Keychain service `com.ultimatesup.openmemory.backup-key`,
account `allen_bot`, through file descriptor 3. Plaintext manifests,
checksums, journals, and state remain local. The state
`protected_local_verified` does not claim remote File Provider confirmation.
The HMAC manifest record lives outside mutable run directories. Canonical
compact UTF-8 JSON covers source manifests, runtime/data checksums, archive
names and digests, and production fingerprints. Missing, changed, duplicate,
unknown, or prompt-required Keychain state fails closed. The manifest item is
restricted to `/usr/bin/security`; the existing encryption item additionally
permits Apple's `/Library/Developer/CommandLineTools/usr/bin/swift-frontend`,
which is an explicitly accepted trusted application and does not change the
existing key.

## Health and recovery

Health is read-only and token-free. It checks backup freshness, atomic state,
checksums, protected state, unauthenticated `/healthz`, expected middleware
`401`, Qdrant readiness, disk headroom, and structured local port bindings.
Missing, stale, locked, malformed, failed, deadline, retention, publication,
or notification state is red. Markers are atomic and redacted.

If a coordinator is killed during maintenance, its watchdog records a durable
recovery state, terminates its coordinator-owned process group, verifies that
the group is gone, and then attempts to restore the previously running
services. Docker context and Compose inputs are explicit; ambient overrides are
rejected. Failed run directories are retained for diagnosis. No secure-erasure
claim is made for APFS/SSD residue.
