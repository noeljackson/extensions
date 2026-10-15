#!/usr/bin/env python3
"""Offline fixtures for payload, provenance and publication admission failures."""
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
import tarfile
import tempfile
import unittest
import build
import verify

REV = 'a' * 40
MANIFEST = b'version: v1alpha1\n'
MODULE = b'signed module bytes preserved verbatim'
MODULE_PATH = 'rootfs/usr/lib/modules/6.18.48-talos/extras/drbd.ko'
LOCK = dict(version='9.3.3-v1.14.0-wg-fixture', kernel='ghcr.io/noeljackson/kernel@sha256:' + 'b' * 64,
            package='ghcr.io/noeljackson/drbd-pkg@sha256:' + 'c' * 64, revision='d' * 40,
            payload_files={MODULE_PATH: hashlib.sha256(MODULE).hexdigest()})


def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode()


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fixture(self, change=None, wrapped=False):
        state = dict(payload={MODULE_PATH: MODULE, 'manifest.yaml': MANIFEST}, mode=0o644,
                     arch='amd64', owner=0, labels={}, subject=None,
                     predicates=['https://slsa.dev/provenance/v1', 'https://spdx.dev/Document'])
        if change:
            change(state)
        blobs = {}

        def blob(data, media):
            key = verify.digest(data)
            blobs['blobs/sha256/' + key.split(':')[1]] = data
            return dict(digest=key, size=len(data), mediaType=media)

        config = dict(architecture=state['arch'], os='linux', config=dict(Labels={
            'org.opencontainers.image.source': 'https://github.com/noeljackson/extensions',
            'org.opencontainers.image.revision': REV, 'org.opencontainers.image.title': 'drbd',
            'org.opencontainers.image.version': LOCK['version'], 'io.codewire.kernel.package': LOCK['kernel'],
            'io.codewire.drbd.package': LOCK['package'], 'io.codewire.pkgs.revision': LOCK['revision'],
            **state['labels']}))
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode='w:gz') as archive:
            for name, data in state['payload'].items():
                member = tarfile.TarInfo(name)
                member.mode, member.uid, member.gid, member.size = state['mode'], state['owner'], state['owner'], len(data)
                archive.addfile(member, io.BytesIO(data))
        image = blob(encoded(dict(schemaVersion=2,
                                config=blob(encoded(config), 'application/vnd.oci.image.config.v1+json'),
                                layers=[blob(layer.getvalue(), 'application/vnd.oci.image.layer.v1.tar+gzip')])),
                     'application/vnd.oci.image.manifest.v1+json')
        image['platform'] = dict(architecture=state['arch'], os='linux')
        subject = state['subject'] or image['digest']
        attest = blob(encoded(dict(schemaVersion=2, subject=dict(image, digest=subject),
                                 config=blob(b'{}', 'application/vnd.oci.image.config.v1+json'),
                                 layers=[blob(encoded(dict(_type='https://in-toto.io/Statement/v1',
                                                           predicateType=p, predicate={'fixture': True}, subject=[])),
                                              'application/vnd.in-toto+json') for p in state['predicates']])),
                      'application/vnd.oci.image.manifest.v1+json')
        attest.update(platform=dict(architecture='unknown', os='unknown'), annotations={
            'vnd.docker.reference.type': 'attestation-manifest', 'vnd.docker.reference.digest': subject})
        index = encoded(dict(schemaVersion=2, mediaType='application/vnd.oci.image.index.v1+json', manifests=[image, attest]))
        if wrapped:
            index = encoded(dict(schemaVersion=2, manifests=[blob(index, 'application/vnd.oci.image.index.v1+json')]))
        files = dict(blobs, **{'index.json': index, 'oci-layout': b'{"imageLayoutVersion":"1.0.0"}'})
        path = self.root / 'fixture.tar'
        with tarfile.open(path, 'w') as out:
            for name, data in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                out.addfile(member, io.BytesIO(data))
        return path

    def inspect(self, path):
        return verify.inspect(path, REV, LOCK, MANIFEST)

    def test_complete_payload_and_attestations_accept_both_index_shapes(self):
        for wrapped in (False, True):
            receipt, _ = self.inspect(self.fixture(wrapped=wrapped))
            self.assertTrue(receipt['module_bytes_unchanged'])
            self.assertFalse(receipt['runtime_accepted'])

    def test_missing_extra_and_changed_module_bytes_fail(self):
        for kind in ('missing', 'extra', 'changed'):
            def change(s):
                if kind == 'missing':
                    del s['payload'][MODULE_PATH]
                elif kind == 'extra':
                    s['payload']['rootfs/private-signing.key'] = b'forbidden'
                else:
                    s['payload'][MODULE_PATH] = b'resigned or different module'
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.inspect(self.fixture(change))

    def test_every_source_label_is_bound(self):
        keys = ('org.opencontainers.image.source', 'org.opencontainers.image.revision',
                'org.opencontainers.image.title', 'org.opencontainers.image.version',
                'io.codewire.kernel.package', 'io.codewire.drbd.package', 'io.codewire.pkgs.revision')
        for key in keys:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'labels'):
                self.inspect(self.fixture(lambda s: s['labels'].update({key: 'foreign'})))

    def test_wrong_platform_modes_ownership_and_manifest_fail(self):
        changes = [lambda s: s.update(arch='arm64'), lambda s: s.update(mode=0o4644),
                   lambda s: s.update(owner=1000), lambda s: s['payload'].update({'manifest.yaml': b'foreign'})]
        for change in changes:
            with self.assertRaises(ValueError):
                self.inspect(self.fixture(change))

    def test_missing_attestation_and_wrong_subject_fail(self):
        for change in [lambda s: s.update(predicates=['https://spdx.dev/Document']),
                       lambda s: s.update(subject='sha256:' + 'f' * 64)]:
            with self.assertRaises(ValueError):
                self.inspect(self.fixture(change))

    def test_corrupt_oci_blob_fails(self):
        path = self.fixture()
        with tarfile.open(path, 'a') as out:
            member = tarfile.TarInfo('blobs/sha256/' + '0' * 64)
            member.size = 3
            out.addfile(member, io.BytesIO(b'bad'))
        with self.assertRaisesRegex(ValueError, 'corrupt OCI blob'):
            self.inspect(path)

    def test_outer_links_traversal_and_duplicates_fail(self):
        for kind in ('link', 'escape', 'duplicate'):
            path = self.fixture()
            with tarfile.open(path, 'a') as out:
                member = tarfile.TarInfo('../escape' if kind == 'escape' else 'index.json')
                if kind == 'link':
                    member.type, member.linkname = tarfile.SYMTYPE, '/etc/passwd'
                out.addfile(member)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.inspect(path)

    def test_materialization_does_not_restore_root_ownership(self):
        _, files = self.inspect(self.fixture())
        layout = self.root / 'layout'
        verify.materialize(files, layout)
        for name, data in files.items():
            self.assertEqual((layout / name).read_bytes(), data)
        with self.assertRaises(ValueError):
            verify.materialize(files, layout)

    def test_publication_requires_exact_deployment_push(self):
        env = dict(GITHUB_ACTIONS='true', GITHUB_EVENT_NAME='push', GITHUB_REPOSITORY='noeljackson/extensions',
                   GITHUB_REF='refs/heads/downstream/confidential-storage', GITHUB_SHA=REV)
        build.require_push(env, REV)
        for key in env:
            changed = copy.deepcopy(env)
            changed[key] = 'foreign'
            with self.subTest(key=key), self.assertRaises(ValueError):
                build.require_push(changed, REV)


if __name__ == '__main__':
    unittest.main()
