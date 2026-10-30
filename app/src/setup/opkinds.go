package setup

// OpKinds are the project op kinds the guided flow and the TUI project editor
// can emit. The parity test fails when projectfile gains a kind that is in
// neither this list nor NotYet, so a new kind has to be decided on here.
var OpKinds = []string{
	"set_envs", "set_tech", "remove_tech", "set_env_tech", "remove_env_tech",
	"set_image", "add_lockfile", "remove_lockfile", "set_since", "set_lockfile_dev",
}

// NotYet are kinds no guided front end emits yet. Whoever adds the editing
// field moves the kind to OpKinds; the test fails if a kind is in both.
var NotYet = []string{}
