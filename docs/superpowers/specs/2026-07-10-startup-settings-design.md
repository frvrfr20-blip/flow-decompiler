# Startup Settings Design

## Goal

Let users enable or disable launching Flow Decompiler at Windows sign-in from the existing UI. Startup launches the app minimized without opening a console window. Document Flow's local and MCP-assisted workflows in the Roblox executor skill so future agents use it directly.

## UI

- Add a Lucide settings button to the header.
- Open a small modal containing one checkbox: `Launch at sign-in`.
- Reflect the saved setting when the dialog opens.
- Apply the change immediately and report success or failure in the existing status bar.

## Settings And Startup

- Store settings in `%LOCALAPPDATA%\FlowDecompiler\settings.json`.
- Use the per-user Windows Startup folder, not the registry or Task Scheduler.
- Create `Flow Decompiler.lnk` targeting the current environment's `pythonw.exe` with `-m luau_decompiler.ui --minimized`.
- Remove the shortcut when the option is disabled or Flow is uninstalled.
- Add `--minimized` to the UI entry point and iconify the window after construction.
- Keep startup operations idempotent and preserve a usable UI if settings are missing, malformed, or unwritable.

## Skill Workflow

- Make Flow the primary bytecode decompiler.
- Document the repository, installed CLI/UI commands, accepted file formats, and output modes.
- Document MCP capture through `getscriptbytecode`, base64 encoding, and the local receiver.
- Use lua.expert and Fission as second opinions for important or conflicting output.
- Require bytecode evidence or runtime validation when providers disagree.

## Testing

- Unit-test settings defaults, malformed settings, round trips, startup command construction, shortcut enable/disable behavior through injected filesystem/shortcut boundaries, and `--minimized` parsing.
- Run the complete suite and Python compilation.
- Validate the edited skill with `quick_validate.py`.
- Launch the UI for a visual smoke check without enabling the real startup shortcut during tests.
