#!/usr/bin/env python3
"""Build a deterministic source archive, manifest and distribution SPDX SBOM.

No signing/certification claim is made. Signing keys belong to a separate release
system; this offline builder never reads credentials or calls external services.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile

from assurance_common import digest


def build_release(root: Path, output: Path, paths: list[str], version: str, commit: str):
    root = root.resolve()
    output = output.resolve()
    if output == root or root in output.parents:
        raise ValueError("release output must be outside the source tree")
    if len(set(paths)) != len(paths) or not paths:
        raise ValueError("source paths must be unique and non-empty")
    manifest_files = []
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(paths):
            relative = PurePosixPath(name)
            if (relative.is_absolute() or ".." in relative.parts or ".git" in relative.parts
                    or "\\" in name or ":" in name or str(relative) != name):
                raise ValueError(f"unsafe source path: {name}")
            path = root / name
            if path.is_symlink() or not path.is_file() or root not in path.resolve().parents:
                raise ValueError(f"non-regular/escaping source file: {name}")
            data = path.read_bytes()
            sha = hashlib.sha256(data).hexdigest()
            mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), mode, 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
            manifest_files.append({"path":name, "sha256":sha, "size_bytes":len(data), "mode":mode})
    packed = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=packed, mode="wb", mtime=0, compresslevel=9) as gz:
        gz.write(archive.getvalue())
    data = packed.getvalue()
    release_sha = hashlib.sha256(data).hexdigest()
    manifest = {"schema_version":"0.1", "product_id":"e2eesa-reference", "version":version,
                "source_commit":commit, "source_inventory_digest":digest(manifest_files),
                "artifact_name":"e2eesa-source.tar.gz", "artifact_digest":"sha256:"+release_sha,
                "files":manifest_files}
    sbom = {
        "spdxVersion":"SPDX-2.3", "dataLicense":"CC0-1.0", "SPDXID":"SPDXRef-DOCUMENT",
        "name":"E2EESA source distribution", "documentNamespace":"https://endtoendeverywhere.org/spdx/"+release_sha,
        "creationInfo":{"creators":["Tool: e2eesa-reference-release-0.1.0"], "created":"1970-01-01T00:00:00Z"},
        "packages":[{"name":"E2EESA source", "SPDXID":"SPDXRef-E2EESA", "versionInfo":version,
                     "downloadLocation":"NOASSERTION", "filesAnalyzed":False,
                     "checksums":[{"algorithm":"SHA256", "checksumValue":release_sha}],
                     "licenseConcluded":"NOASSERTION", "licenseDeclared":"NOASSERTION",
                     "copyrightText":"NOASSERTION"}],
        "relationships":[{"spdxElementId":"SPDXRef-DOCUMENT", "relationshipType":"DESCRIBES", "relatedSpdxElement":"SPDXRef-E2EESA"}],
        "comment":"Distribution scope: tracked source only. Runtime, CI and build dependencies require separate inventories. Creation time is a fixed reproducibility epoch, not an assessment timestamp.",
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "e2eesa-source.tar.gz").write_bytes(data)
    (output / "release-manifest.json").write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n")
    (output / "sbom.spdx.json").write_text(json.dumps(sbom,sort_keys=True,indent=2)+"\n")
    return manifest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    if subprocess.check_output(["git","status","--porcelain"],cwd=root).strip():
        parser.error("source checkout must be clean before release construction")
    commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=root).decode().strip()
    files=subprocess.check_output(["git","ls-files","-z"],cwd=root).decode().strip("\0").split("\0")
    manifest=build_release(root,args.output,files,(root/"VERSION").read_text().strip(),commit)
    print(json.dumps({"artifact_digest":manifest["artifact_digest"],"files":len(files)}))


if __name__ == "__main__": main()
