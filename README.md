# cordon

Embeddable, customizable rootless containerization for Rust.

## Milestones

- [x] M1: Steel Thread
- [x] M2: Mount Namespace and Filesystem Control
- [x] M3: PID namespace and UID mapping
- [ ] M4: Control groups

### M1: Steel Thread

A complete, yet limited, working implementation of the library, which can spawn a user-specified program in a user namespace.
_This milestone will be complete when "whoami", run in the sandbox, returns "root."_

### M2: Mount Namespace and Filesystem Control

We'll add the facility to enter a mount namespace in the sandbox, to change the apparent root of the sandboxed program, and to manipulate the mount table inside the sanbdox.
_This milestone will be complete when the output of "ls /" differs inside and outside the sandbox._

### M3: PID namespace, UID mapping

We'll add the ability to place the sandboxed program in a PID namespace, and to map user IDs inside the sandbox to user IDs outside the sandbox.
_This milestone will be complete when files written inside the sandbox appear to the host as owned by the outer process's user ID, and when "sh -c 'echo $$'" returns 1 inside the sandbox._

### M4: Control groups

We'll add the ability to place the sandboxed child process in a Linux control group, and allow the caller to set its parameters.
\*This milestone will be complete when the
