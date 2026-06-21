# TODO-274: Tauri capabilities.json Empty - No Permission Restrictions

## Severity: HIGH

## Source
Cross-model forensic audit (2026-03-22). Found by 3/5 models, verified: file contains exactly `{}`.

## Problem
`apps/tauri/src-tauri/gen/schemas/capabilities.json` is `{}` (empty object).

All Tauri IPC commands have unrestricted default permissions:
- `clipboard_read_text` - clipboard access without explicit permission
- `save_state` / `load_state` - filesystem access
- `engine_connect` / `engine_disconnect` - network operations
- No WebView sandboxing configuration

## Fix
Create `apps/tauri/src-tauri/capabilities/main.json` with minimal permissions:
```json
{
  "identifier": "main-capability",
  "description": "Main window permissions",
  "windows": ["main"],
  "permissions": [
    "core:default",
    "clipboard-manager:default",
    "shell:default"
  ]
}
```

Then regenerate schemas with `cargo tauri dev` or `cargo tauri build`.

## Notes
- This is a generated file (`gen/schemas/`) - may need Tauri CLI to populate correctly
- Tauri 2 uses capability-based permission model; empty = permissive

## Verification
- `capabilities.json` is non-empty after regeneration
- Desktop app still functions with restricted permissions
- No IPC command works without explicit capability grant
