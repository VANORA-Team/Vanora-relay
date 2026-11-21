"""Build one Android AAR with Kotlin/Java bindings, Keystore storage, and native libraries."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    sdk = Path(os.environ.get("ANDROID_HOME") or os.environ["ANDROID_SDK_ROOT"])
    platforms = sorted((p for p in (sdk / "platforms").glob("android-*") if p.name[8:].isdigit()),
                       key=lambda p: int(p.name[8:]))
    android_jar = platforms[-1] / "android.jar"
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    env = os.environ.copy()
    # gomobile invokes gobind by name. Keep tool binaries isolated from the app module.
    with tempfile.TemporaryDirectory(dir=dist) as tmp:
        work = Path(tmp)
        env["GOBIN"] = str(work)
        env["PATH"] = str(work) + os.pathsep + env["PATH"]
        subprocess.run(["go", "install", "golang.org/x/mobile/cmd/gobind", "golang.org/x/mobile/cmd/gomobile"],
                       cwd=ROOT, env=env, check=True)
        aar = work / "vanora-mobile.aar"
        tool = shutil.which("gomobile", path=env["PATH"])
        # Pion's Android interface enumerator (anet v0.0.5) accesses the Go zone cache.
        subprocess.run([tool, "bind", "-target=android/arm64,android/amd64", "-androidapi", "23",
                        "-ldflags=-checklinkname=0", "-o", str(aar), "./mobile"], cwd=ROOT, env=env, check=True)
        classes = work / "classes.jar"
        dest = work / "java"
        dest.mkdir()
        with zipfile.ZipFile(aar) as archive:
            classes.write_bytes(archive.read("classes.jar"))
        subprocess.run(["javac", "--release", "8", "-cp", os.pathsep.join(map(str, [android_jar, classes])),
                        "-d", str(dest), str(Path(__file__).with_name("AndroidAccountStore.java"))], check=True)
        subprocess.run(["jar", "uf", str(classes), "-C", str(dest), "."], check=True)
        packed = work / "packed.aar"
        with zipfile.ZipFile(aar) as source, zipfile.ZipFile(packed, "w") as target:
            for entry in source.infolist():
                if entry.filename == "classes.jar":
                    target.writestr(entry, classes.read_bytes())
                else:
                    target.writestr(entry, source.read(entry))
        os.replace(packed, dist / aar.name)
        print(dist / aar.name)


if __name__ == "__main__":
    main()
