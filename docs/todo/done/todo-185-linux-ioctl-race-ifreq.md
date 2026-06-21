# TODO-185: Linux ioctl IfReq Uninitialized Memory

## Status
COMPLETED

## Severity
MEDIUM

## Context
The Linux TUN interface setup copies the interface name into an `ifreq` struct's `ifr_name` field, but may leave trailing bytes uninitialized (or only zero-initialized via `mem::zeroed`). If the name is shorter than `IFNAMSIZ` (16 bytes), the remaining bytes depend on `mem::zeroed` correctness. Additionally, the string reconstruction from `ifr_name` assumes a null terminator exists.

- `src/implementations/client/platform/linux.rs:137-149`: name copy into `ifr_name` via `.take(len)` clips to name length
- Leftover bytes in `ifr_name` buffer after the name rely on `mem::zeroed` initialization
- `src/implementations/client/platform/linux.rs:155-160`: string reconstruction from `ifr_name` assumes null-terminated C string
- If `mem::zeroed` is bypassed or the struct is stack-allocated without zeroing, UB can occur

## Root Cause
The ioctl interface requires C-style null-terminated strings in fixed-size buffers. The Rust code uses `mem::zeroed` which should zero the buffer, but the code does not explicitly null-terminate after the name copy, relying on the pre-zeroed state. This is fragile and violates defense-in-depth.

## Fix Plan
1. After copying the name into `ifr_name`, explicitly write a null byte at position `name.len()`:
   ```rust
   ifr.ifr_name[name.len()] = 0;
   ```
2. Add bounds check: ensure `name.len() < IFNAMSIZ` (not `<=`, to leave room for null terminator)
3. Validate ioctl return value explicitly (check for -1 and map errno)
4. For string reconstruction (line 155-160): use `CStr::from_ptr` or find null terminator explicitly instead of assuming position
5. Add unit test with max-length interface name (15 chars + null)

## Acceptance Criteria
- `ifr_name` explicitly null-terminated after name copy
- Name length validated against `IFNAMSIZ - 1`
- ioctl return value checked and mapped to proper error
- String reconstruction uses explicit null-terminator search
- Unit test covers edge case (15-char name)

## Dependencies
- None

## Affected Files
- `src/implementations/client/platform/linux.rs`
