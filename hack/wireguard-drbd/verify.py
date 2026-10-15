#!/usr/bin/env python3
"""Verify the complete DRBD extension payload and its OCI descriptor chain."""
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

HERE = Path(__file__).resolve().parent


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def archive_files(path):
    files = {}
    total = 0
    with tarfile.open(path) as archive:
        seen = set()
        for member in archive:
            name = member.name.rstrip('/')
            require(name not in seen, 'duplicate OCI member')
            seen.add(name)
            if member.isdir():
                require(name in ('blobs', 'blobs/sha256'), 'unexpected OCI directory')
                continue
            require(member.isfile() and (name in ('index.json', 'oci-layout')
                    or re.fullmatch('blobs/sha256/[0-9a-f]{64}', name)), 'unexpected OCI member')
            total += member.size
            require(0 <= member.size <= 32 * 1024**2 and total <= 64 * 1024**2, 'oversized OCI archive')
            files[name] = archive.extractfile(member).read()
            if name.startswith('blobs/'):
                require(digest(files[name]) == 'sha256:' + name.split('/')[-1], 'corrupt OCI blob')
    require(json.loads(files['oci-layout']) == {'imageLayoutVersion': '1.0.0'}, 'wrong OCI layout')
    return files


def inspect(path, revision, lock=None, expected_manifest=None):
    lock = lock or json.loads((HERE / 'package.lock.json').read_text())
    expected_manifest = expected_manifest or (HERE / 'manifest.yaml').read_bytes()
    require(re.fullmatch('[0-9a-f]{40}', revision), 'full extension revision required')
    files = archive_files(path)

    def blob(desc):
        require(re.fullmatch('sha256:[0-9a-f]{64}', desc['digest']) and not desc.get('urls'), 'invalid descriptor')
        data = files['blobs/sha256/' + desc['digest'].split(':')[1]]
        require(len(data) == desc['size'] and digest(data) == desc['digest'], 'descriptor mismatch')
        return data

    index_raw = files['index.json']
    index = json.loads(index_raw)
    # Buildx may wrap its image/attestation index in the layout's selector index.
    if len(index['manifests']) == 1 and index['manifests'][0]['mediaType'] == 'application/vnd.oci.image.index.v1+json':
        index_raw = blob(index['manifests'][0])
        index = json.loads(index_raw)
    require(index.get('schemaVersion') == 2 and len(index['manifests']) == 2, 'image and attestation pair required')
    images = [d for d in index['manifests'] if d.get('platform') == {'architecture': 'amd64', 'os': 'linux'}]
    attestations = [d for d in index['manifests'] if d.get('annotations', {}).get('vnd.docker.reference.type') == 'attestation-manifest']
    require(len(images) == len(attestations) == 1, 'one amd64 image and attestation required')
    image, attestation = images[0], attestations[0]
    require(attestation['annotations']['vnd.docker.reference.digest'] == image['digest'], 'attestation subject differs')
    manifest = json.loads(blob(image))
    config = json.loads(blob(manifest['config']))
    require(config.get('architecture') == 'amd64' and config.get('os') == 'linux', 'wrong image platform')
    labels = config.get('config', {}).get('Labels', {})
    expected = {'org.opencontainers.image.source': 'https://github.com/noeljackson/extensions',
                'org.opencontainers.image.revision': revision,
                'org.opencontainers.image.title': 'drbd',
                'org.opencontainers.image.version': lock['version'],
                'io.codewire.kernel.package': lock['kernel'],
                'io.codewire.drbd.package': lock['package'],
                'io.codewire.pkgs.revision': lock['revision']}
    require(all(labels.get(k) == v for k, v in expected.items()), 'source/package labels differ')
    require(len(manifest['layers']) == 1, 'one complete extension layer required')
    layer = blob(manifest['layers'][0])
    expected_files = dict(lock['payload_files'], **{'manifest.yaml': hashlib.sha256(expected_manifest).hexdigest()})
    allowed_dirs = {str(parent) for name in expected_files for parent in Path(name).parents if str(parent) != '.'}
    found, seen, total = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(layer)) as payload:
        for member in payload:
            name = member.name.rstrip('/')
            require(name not in seen and member.uid == member.gid == 0, 'duplicate or non-root payload member')
            seen.add(name)
            if member.isdir():
                require(name in allowed_dirs and member.mode & 0o7777 == 0o755, 'unexpected payload directory')
                continue
            require(member.isfile() and name in expected_files and member.mode & 0o7777 == 0o644, 'unexpected payload file')
            total += member.size
            require(0 <= member.size <= 16 * 1024**2 and total <= 32 * 1024**2, 'oversized payload')
            found[name] = hashlib.sha256(payload.extractfile(member).read()).hexdigest()
    require(found == expected_files, 'module or manifest bytes differ')
    att = json.loads(blob(attestation))
    blob(att['config'])
    if 'subject' in att:
        require(att['subject']['digest'] == image['digest'], 'OCI attestation subject differs')
    predicates = set()
    for desc in att['layers']:
        statement = json.loads(blob(desc))
        require(statement.get('_type') == 'https://in-toto.io/Statement/v1', 'invalid attestation statement')
        require(statement.get('predicate'), 'empty attestation predicate')
        for subject in statement.get('subject', []):
            require(subject.get('digest', {}).get('sha256') == image['digest'].split(':')[1], 'statement subject differs')
        predicates.add(statement['predicateType'])
    require(predicates == {'https://slsa.dev/provenance/v1', 'https://spdx.dev/Document'}, 'provenance and SBOM required')
    return {'index': digest(index_raw), 'platform_manifest': image['digest'], 'revision': revision,
            'kernel_package': lock['kernel'], 'drbd_package': lock['package'],
            'payload_files': len(found), 'module_bytes_unchanged': True,
            'runtime_accepted': False}, files


def materialize(files, path):
    require(not path.exists(), 'layout exists')
    path.mkdir(mode=0o700)
    for name, data in files.items():
        target = path / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
        target.chmod(0o600)
