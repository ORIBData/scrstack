#!/usr/bin/env python3
"""Record package scan and SBOM evidence for an immutable local SCRS image ID."""
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    docker = os.environ.get('DOCKER', 'docker')
    reference = os.environ['SCRS_IMAGE']
    image_id = subprocess.check_output([docker, 'image', 'inspect', '--format', '{{.Id}}', reference], text=True).strip()
    directory = Path('artifacts') / image_id.removeprefix('sha256:')
    directory.mkdir(parents=True, exist_ok=True)
    cves, sbom = directory/'vulnerabilities.sarif', directory/'sbom.cdx.json'
    subprocess.run([docker,'scout','cves','--format','sarif','--output',str(cves),'local://'+image_id],check=True)
    subprocess.run([docker,'scout','sbom','--format','cyclonedx','--output',str(sbom),'local://'+image_id],check=True)
    report=json.loads(cves.read_text())
    findings=sum(len(run.get('results',[])) for run in report.get('runs',[]))
    if not report.get('runs'):
        raise ValueError('Scanner returned no assessment runs')
    metadata={'image_id':image_id,'reference':reference,'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'findings':findings}
    (directory/'image.json').write_text(json.dumps(metadata,indent=2)+'\n')
    print(f'Image evidence: {directory}; reported findings: {findings}')
    return 1 if findings else 0


if __name__=='__main__':
    try:
        sys.exit(main())
    except (subprocess.CalledProcessError,KeyError,ValueError) as exc:
        sys.exit(f'Image audit failed: {exc}')
