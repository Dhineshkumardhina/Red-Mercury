"""Download and install official Gitleaks Windows x64 binary into bin/."""
import io
import os
from pathlib import Path
import urllib.request
import zipfile

def main():
    project_root = Path(__file__).resolve().parent.parent
    bin_dir = project_root / "bin"
    bin_dir.mkdir(exist_ok=True)
    gitleaks_exe = bin_dir / "gitleaks.exe"

    if gitleaks_exe.exists():
        print(f"Gitleaks already exists at: {gitleaks_exe}")
        return

    url = "https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_windows_x64.zip"
    print(f"Downloading Gitleaks from: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        zip_data = resp.read()

    print(f"Downloaded {len(zip_data)} bytes. Extracting to {bin_dir}...")
    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        for member in zf.namelist():
            if member.endswith("gitleaks.exe") or member.endswith("gitleaks"):
                with zf.open(member) as src, open(gitleaks_exe, "wb") as dst:
                    dst.write(src.read())
                print(f"Extracted {member} -> {gitleaks_exe}")

    print("Gitleaks installation complete.")

if __name__ == "__main__":
    main()

