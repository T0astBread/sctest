## Debugging

To start an interactive debugger on either the execer or the monitor
process, use the `scripts/attach-debugger-to` script. Start the
program with `scripts/start-dbg` and then run a command like:

```
scripts/attach-debugger-to <execer|monitor> <headless|interactive>
```

`headless` starts Delve in remote mode, suitable for debugging in VS
Code.

`interactive` starts the Delve terminal interface.

If you need to debug some initialization steps, set the
`SCT_DEBUG_WAIT` environment variable. If it contains the substring
`execer` or `monitor`, the respective processes will wait for ten
seconds before doing any meaningful work, giving you time to attach
a debugger.

In VS Code, the `Execer` and `Monitor` launch configurations can be
used to *connect to* the respective headless debuggers. They do not
launch the program or the debugger.

A typical debugging setup would involve the following steps:

1. Start the program:
   `SCT_DEBUG_WAIT=execer,monitor scripts/start-dbg`
2. Start the execer debugger:
   `scripts/attach-debugger-to execer headless`
3. Run the `Execer` launch config from VS Code
4. Start the monitor debugger:
   `scripts/attach-debugger-to monitor headless`
5. Run the `Monitor` launch config from VS Code

Note that the `attach-debugger-to` scripts can also be started before
the program itself though this is not really useful since the timer
will run to completion anyways.
