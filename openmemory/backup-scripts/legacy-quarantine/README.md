# Legacy operations quarantine

The former logical-export script remains outside the replacement ownership
boundary and is never invoked by the replacement jobs. The installer archives
the prior LaunchAgent plist copies before bootstrapping replacements. Keep any
legacy copies owner-only and non-executable until a separate audit proves they
are safe to remove.
