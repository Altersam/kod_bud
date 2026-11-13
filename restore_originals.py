#!/usr/bin/env python3
"""Restore exact upstream HTML for lessons 7–9 and archived index, then apply course enhancements.

Uses pinned Git blob SHA-1 values observed in the public repository on 2026-11-13.
Run with: python restore_originals.py
Requires network access to api.github.com. Optional; the ZIP is fully navigable without it.
"""
import argparse, base64, hashlib, json, subprocess, sys
from pathlib import Path
from urllib.request import Request, urlopen

PINNED={
 'lesson_7.html':'d5d746869272f7cb44571cec3641c06438c73016',
 'lesson_8.html':'2a7ded8d8c2ae19a457dc8d08b713110e45c384f',
 'lesson_9.html':'144a93103fc108745b1bbf1cdeaf644ab2937110',
 'extra_structures_legacy.html':'052d08507d3c1e406be6bc859f961315dda0bf52',
}

def fetch_blob(sha):
    url=f'https://api.github.com/repos/Altersam/kod_bud/git/blobs/{sha}'
    req=Request(url,headers={'Accept':'application/vnd.github+json','User-Agent':'kod-bud-module1-restore'})
    with urlopen(req,timeout=30) as f:
        obj=json.load(f)
    if obj.get('encoding')!='base64':raise ValueError(f'Unexpected encoding: {obj.get("encoding")}')
    payload=base64.b64decode(obj['content'])
    git_hash=hashlib.sha1(f'blob {len(payload)}\0'.encode()+payload).hexdigest()
    if git_hash!=sha:raise ValueError(f'Checksum mismatch for {sha}: {git_hash}')
    return payload

def run():
    root=Path(__file__).resolve().parent
    for filename,sha in PINNED.items():
        raw=fetch_blob(sha)
        (root/filename).write_bytes(raw)
        print('restored original:', filename, len(raw))
    subprocess.run([sys.executable,str(root/'build_course.py'),'--root',str(root),'--strict'],check=True)
    print('Done: originals 7–9 restored and enhanced; legacy index archived in root.')

if __name__=='__main__':
    try:run()
    except Exception as exc:
        print('Restoration unavailable:',exc,file=sys.stderr)
        print('The enclosed HTML pages remain functional as independent offline pages.',file=sys.stderr)
        sys.exit(1)
