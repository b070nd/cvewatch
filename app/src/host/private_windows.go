//go:build windows

package host

// Private reports whether the OS enforces the 0600/0700 modes. It is true on
// unix (Linux, macOS), where the modes restrict access to the owner.
// On Windows it is false: the modes are ignored and owner-only access relies
// on the ACLs inherited from the user profile directory.
func Private() bool { return false }
