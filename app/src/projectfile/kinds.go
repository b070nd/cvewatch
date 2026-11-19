package projectfile

// Kind names an op kind. Every kind is a constant here and a row in OpTable,
// so a misspelt kind does not compile and a new one is decided on in one place.
type Kind string

const (
	KindSetEnvs        Kind = "set_envs"
	KindAddEnv         Kind = "add_env"
	KindRemoveEnv      Kind = "remove_env"
	KindRenameEnv      Kind = "rename_env"
	KindSetTech        Kind = "set_tech"
	KindRemoveTech     Kind = "remove_tech"
	KindSetEnvTech     Kind = "set_env_tech"
	KindRemoveEnvTech  Kind = "remove_env_tech"
	KindExcludeEnvTech Kind = "exclude_env_tech"
	KindIncludeEnvTech Kind = "include_env_tech"
	KindSetTechEnvs    Kind = "set_tech_envs"
	KindSetImage       Kind = "set_image"
	KindMigrateEnvs    Kind = "migrate_envs"
	KindAddLockfile    Kind = "add_lockfile"
	KindRemoveLockfile Kind = "remove_lockfile"
	KindSetLockfileDev Kind = "set_lockfile_dev"
	KindSetSince       Kind = "set_since"
	KindSetVendor      Kind = "set_vendor"
	KindSetOwner       Kind = "set_owner"
	KindSetProfile     Kind = "set_profile"
	KindSetUpdate      Kind = "set_update"
)
