Signals arriving from Gateway (POST /score/initial)


{
  src_ip: "185.220.101.34",        src_port: 45122,
  client_version: "OpenSSH_8.4p1", kex_algorithms_hash: "a3f2b9c10d4e",
  time_to_first_auth: 0.85,        auth_attempts_count: 3,
  auth_methods_used: ["password"],  usernames_tried: ["root", "admin"],
  public_key_attempted: false,      shell_requested: false,
  exec_command: null,               is_interactive: false,
  auth_attempt_interval: 0.45
}



Tier 1: Heuristic Rules Engine (0ms, no I/O)
What it does: Stateless pattern matching. Checks signals against 9 hardcoded rules in priority order. First match wins — no further rules evaluated.
[]
