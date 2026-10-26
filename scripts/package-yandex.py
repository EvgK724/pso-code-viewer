#!/usr/bin/env python3
"""Build a private, setup-only Yandex Cloud Functions ZIP. Python 3.7+."""
import argparse
import json
from pathlib import Path
import re
import shutil
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]

def build(output,endpoint,database):
    output=Path(output).resolve()
    if output.exists():
        raise ValueError('Output already exists')
    if not re.fullmatch(r'grpcs://[a-z0-9.-]+:[0-9]{1,5}',endpoint):
        raise ValueError('Expected a grpcs endpoint')
    if not re.fullmatch(r'/ru-central1/[a-z0-9]+/[a-z0-9]+',database):
        raise ValueError('Expected the Russian YDB database path')
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory() as folder:
        temp=Path(folder)
        shutil.copytree(str(ROOT/'docs'),str(temp/'docs'))
        for path in (ROOT/'server').rglob('*.mjs'):
            if path.name.endswith('.test.mjs') or path.name=='test-db.mjs':
                continue
            target=temp/path.relative_to(ROOT)
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(str(path),str(target))
        for name in ['package.json','package-lock.json','.npmrc']:
            shutil.copy2(str(ROOT/'server/yandex'/name),str(temp/name))
        (temp/'index.js').write_text("'use strict';\nexports.handler=async (event,context)=>(await import('./server/yandex/entry.mjs')).handler(event,context);\n",encoding='utf-8')
        (temp/'connection.json').write_text(json.dumps({'endpoint':endpoint,'database':database},indent=2)+'\n',encoding='utf-8')
        # Packaged defaults fail closed. Actual addresses come from the explicit
        # PSO_VIEWER_ORIGIN configuration when the router serves these resources.
        (temp/'docs/shortlink-config.mjs').write_text("export const SHORTLINK_ENDPOINT='';\nexport const PUSH_ENDPOINT='';\nexport const TEAM_ENDPOINT='';\nexport const DIRECT_ENDPOINT='';\nexport const DEVICE_AUTH_ENDPOINT='';\n",encoding='utf-8')
        index=temp/'docs/index.html'
        index.write_text(re.sub(r"connect-src 'self' https://[^;\"]+", "connect-src 'self'",index.read_text(encoding='utf-8')),encoding='utf-8')
        shutil.copy2(str(ROOT/'server/yandex/SETUP-RU.txt'),str(temp/'README.txt'))
        with zipfile.ZipFile(str(output),'x',zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(temp.rglob('*')):
                if path.is_file():
                    archive.write(str(path),str(path.relative_to(temp)))
    return output

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True)
    parser.add_argument('--endpoint',required=True)
    parser.add_argument('--database',required=True)
    args=parser.parse_args()
    print(build(args.output,args.endpoint,args.database))
