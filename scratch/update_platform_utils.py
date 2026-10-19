import sys
import re

path = 'utils/platform_utils.py'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

old_content_pattern = r'def get_monitored_directories\(self\) -> List\[Path\]:.*?return \[p for p in paths if p\.exists\(\)\]'

new_content = '''def get_monitored_directories(self) -> List[Path]:
        """Get default directories to monitor (platform-specific)."""
        import os
        import logging
        log = logging.getLogger(__name__)

        home = self.get_home_directory()

        if self.is_windows():
            # Windows default paths
            paths = [
                home / "Documents",
                home / "Desktop",
                home / "Downloads",
            ]
            # Add OneDrive if it exists
            onedrive = home / "OneDrive"
            if onedrive.exists():
                paths.append(onedrive)

            # Return only paths that exist (preserve Windows behavior exactly)
            return [p for p in paths if p.exists()]

        elif self.is_linux() or self.is_macos():
            # Linux/macOS default paths
            paths = [
                home / "Documents",
                home / "Desktop",
                home / "Downloads",
            ]

            # Include only if exists, is a directory, and is readable
            valid_paths = [p for p in paths if p.exists() and p.is_dir() and os.access(p, os.R_OK)]

            # Fallback to home if XDG folders are missing
            if not valid_paths:
                if home.exists() and home.is_dir() and os.access(home, os.R_OK):
                    valid_paths = [home]

            log.debug("Linux/macOS monitored directories: %s", [str(p) for p in valid_paths])
            return valid_paths

        else:
            # Fallback: just home directory
            paths = [home]
            return [p for p in paths if p.exists()]'''

new_file = re.sub(old_content_pattern, new_content, content, flags=re.DOTALL)
if new_file == content:
    print('Failed to replace.')
    sys.exit(1)
with open(path, 'w', encoding='utf-8') as f:
    f.write(new_file)
print('Successfully replaced.')
