# Daemon

`calved` serves the Calve API on a private Unix socket (`daemon.sock` under `$XDG_RUNTIME_DIR/calve/<digest>/` when that is set, otherwise in the Calve data directory; directory mode `0700`, socket `0600`, peer UID checked), and logs to `<data>/logs/daemon.log`. `calve daemon start|stop|restart|status|logs` manage it; `calve daemon serve` runs it in the foreground.

The CLI uses a running daemon automatically and otherwise runs requests in-process with the same code. `--direct` forces in-process execution, `--endpoint <socket>` requires a specific daemon, and `--no-daemon-start` prevents the automatic start that `execution start|retry` and the console otherwise perform. The client makes path arguments absolute, since the daemon has its own working directory. A provider's executable is stored as given, so use an absolute path, and `--env` and `env:` secrets read the daemon's environment.

The daemon keeps one open Project, and therefore one OpenAEVC runtime, per Project root. Queries such as `status`, `execution list` or console refreshes are answered while a long execution runs. Writers remain exclusive through the Project's file lock, and a second concurrent writer gets a retryable `PROJECT_LOCKED`. Replayed request IDs return the original response, and a request still in progress returns a retryable `REQUEST_IN_PROGRESS`.

On `SIGTERM` or Ctrl+C the daemon stops accepting connections, gives in-flight requests five seconds, and removes its socket. After a crash, `daemon start` replaces the stale socket; executions that were running are reported `LOST` once their lease expires.
