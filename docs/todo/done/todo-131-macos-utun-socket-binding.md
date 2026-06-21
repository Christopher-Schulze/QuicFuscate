# TODO-131: macOS utun Socket Binding Not Properly Implemented

## Status
**IMPLEMENTED** - Full utun kernel control socket sequence in macos.rs. Needs runtime testing on macOS.

## Severity
**HIGH**

## Context
In `src/implementations/client/platform/macos.rs:167-193`, a utun socket is created via raw socket syscall but is not properly bound using `sockaddr_ctl`. The code opens the raw socket without completing the utun device binding sequence required by macOS's kernel control interface.

Without proper binding, the utun device is created but not functional for packet I/O - the socket cannot send or receive tunnel traffic.

## Root Cause (resolved)
The utun creation sequence was incomplete - it only did step 1 (socket creation) without
the ioctl/connect binding. Now implements all 4 steps:
1. socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
2. ioctl(CTLIOCGINFO) to resolve "com.apple.net.utun_control" -> ctl_id
3. connect() with SockaddrCtl (sc_id, sc_unit = utun_num + 1)
4. fcntl(O_NONBLOCK) to set non-blocking mode

## Implementation Details
- Added `CtlInfo` and `SockaddrCtl` repr(C) structs matching macOS kernel headers
- Constants: `SYSPROTO_CONTROL`, `AF_SYS_CONTROL`, `CTLIOCGINFO`, `UTUN_CONTROL_NAME`
- `FdGuard` RAII type: auto-closes fd on early return (disarmed on success)
- ifconfig failure after connect also closes the fd properly
- Error messages include `std::io::Error::last_os_error()` for each syscall

## Acceptance Criteria
- macOS TUN device is properly bound via `sockaddr_ctl` and functional for packet I/O
- Socket creation failure properly cleans up resources (fd closed)
- Error messages include specific failure context (ioctl failure vs connect failure)
- Unit test validates the binding sequence (or integration test on macOS CI)

## Dependencies
- macOS-specific syscall constants (`AF_SYSTEM`, `AF_SYS_CONTROL`, `SYSPROTO_CONTROL`, `CTLIOCGINFO`)
- libc crate for struct definitions

## Affected Files
- `src/implementations/client/platform/macos.rs`
- `src/implementations/client/mod.rs` (error propagation)
