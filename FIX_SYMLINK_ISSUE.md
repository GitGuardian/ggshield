# Fix for Issue #1144: Handle Broken Symlinks

## Problem
ggshield crashes when it encounters a broken symlink during file scanning.
Error: `[Errno 2] No such file or directory: '<symlink_path>'`

## Solution
Implement proper error handling to skip broken symlinks and continue scanning.

## Changes Made

### 1. Modified file scanning logic
- Added check for broken symlinks using `os.path.islink()` and `os.path.exists()`
- Skip broken symlinks with appropriate logging
- Continue scanning remaining files instead of crashing

### 2. Error Handling
```python
try:
    # Process file
except (OSError, FileNotFoundError) as e:
    if "No such file or directory" in str(e) or os.path.islink(path):
        # Skip broken symlink
        logger.debug(f"Skipping broken symlink: {path}")
    else:
        raise
```

## Testing
- Added unit tests for broken symlink scenarios
- Verified scan completes successfully with broken symlinks present
- Tested with multiple edge cases

## Expected Result
When a broken symlink is encountered:
- A debug log message is generated
- The symlink is skipped
- The scan continues and completes successfully

## Fixes
- Issue #1144: Invalid symlink causes error in the scan
