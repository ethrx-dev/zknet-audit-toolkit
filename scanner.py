import os
from pathlib import Path


EXCLUDE_DIRS = {'.git', 'node_modules', '__pycache__', '.next', 'build', 'dist', 'target',
                'venv', '.venv', '.cache', '.npm', '.yarn', 'coverage', '.nyc_output',
                'env', '.env', 'site-packages', '.tox', '.eggs', 'eggs', '.mypy_cache',
                '.pytest_cache', '.ruff_cache', '.hypothesis', '.svn'}

EXCLUDE_EXTENSIONS = {'.pyc', '.pyo', '.so', '.o', '.a', '.lib', '.dll', '.dylib',
                      '.exe', '.bin', '.dat', '.db', '.sqlite', '.sqlite3',
                      '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
                      '.mp3', '.mp4', '.avi', '.mov', '.wav', '.flac',
                      '.zip', '.tar', '.gz', '.bz2', '.xz', '.rar', '.7z',
                      '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                      '.ttf', '.otf', '.woff', '.woff2', '.eot',
                      '.map', '.min.js', '.min.css',
                      '.lock', '.log', '.pid'}

SOURCE_EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.rs', '.java', '.rb',
                     '.php', '.c', '.cpp', '.h', '.hpp', '.swift', '.kt', '.scala',
                     '.html', '.vue', '.svelte', '.css', '.scss', '.sass', '.less',
                     '.yaml', '.yml', '.json', '.toml', '.ini', '.cfg', '.conf',
                     '.md', '.mdx', '.sh', '.bash', '.zsh', '.fish',
                     '.dockerfile', '.env', '.env.example',
                     '.mjs', '.cjs', '.mts', '.cts'}

MAX_FILE_SIZE = 1024 * 1024  # 1MB


def iter_source_files(target_dir):
    target = Path(target_dir).resolve()
    for root, dirs, files in os.walk(target):
        # Prune excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for f in files:
            fpath = Path(root) / f
            ext = fpath.suffix.lower()

            # Skip excluded extensions
            if ext in EXCLUDE_EXTENSIONS:
                continue

            # Only scan source files
            if ext not in SOURCE_EXTENSIONS and ext not in ('.env', '.env.example'):
                continue

            # Skip large files
            try:
                if fpath.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            yield fpath


def relative_to(fpath, target):
    try:
        return fpath.relative_to(target)
    except ValueError:
        return fpath
