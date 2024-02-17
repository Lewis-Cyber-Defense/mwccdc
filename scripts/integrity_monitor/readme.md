- Monitors sha256 hashes of the given files (`files.json`) for any changes.

- Will give a warning if any file paths are invalid or don't exist.

- When adding new files to `files.json`, the `real` and `baseline` keys should be created but left blank for the script to populate automatically.

- As of now this will *not* begin monitoring files that are added during program execution. It shouldn't crash outright, but adding new file paths in `files.json` requires the script to be restarted.
