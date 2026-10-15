#!/usr/bin/env python3
"""Build/inspect the matching DRBD extension; only its deployment push publishes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
sys.dont_write_bytecode = True
import tempfile
import verify

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILDKIT = 'moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8'


def require_push(env, revision):
    verify.require(env.get('GITHUB_ACTIONS') == 'true' and env.get('GITHUB_EVENT_NAME') == 'push'
                   and env.get('GITHUB_REPOSITORY') == 'noeljackson/extensions'
                   and env.get('GITHUB_REF') == 'refs/heads/downstream/confidential-storage'
                   and env.get('GITHUB_SHA') == revision, 'exact deployment push required')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['build', 'verify', 'publish'])
    parser.add_argument('output', type=Path)
    parser.add_argument('--no-cache', action='store_true', help='build without cached layers for comparison')
    args = parser.parse_args()
    git = lambda *a: subprocess.check_output(['git', *a], cwd=ROOT, text=True).strip()
    revision = git('rev-parse', 'HEAD')
    epoch = int(git('show', '-s', '--format=%ct', 'HEAD'))
    verify.require(not args.no_cache or args.mode == 'build', '--no-cache requires build mode')
    verify.require(re.fullmatch('[0-9a-f]{40}', revision), 'full source commit required')
    verify.require(not git('status', '--porcelain', '--untracked-files=all'), 'clean checkout required')
    verify.require(not git('ls-files', '--others', '--ignored', '--exclude-standard', 'hack/wireguard-drbd'), 'ignored build input forbidden')
    output = args.output.resolve()
    verify.require(output != ROOT and ROOT not in output.parents, 'outputs must be outside checkout')
    archive = output / 'drbd.oci.tar'
    if args.mode == 'publish':
        require_push(os.environ, revision)
    if args.mode == 'build':
        output.mkdir(mode=0o700)
        version = subprocess.check_output(['docker', 'buildx', 'version'], text=True).split()[1]
        verify.require(version == 'v0.36.1', 'pinned Buildx required')
        builder = subprocess.check_output(['docker', 'buildx', 'inspect', '--timeout', '20s'], text=True)
        verify.require(re.search(r'^Driver:\s+docker-container$', builder, re.M)
                       and ('image="' + BUILDKIT + '"') in builder
                       and len(re.findall(r'^Status:\s+running$', builder, re.M)) == 1, 'one pinned running builder required')
        node = re.findall(r'^Name:\s+(\S+)$', builder, re.M)[-1]
        container = json.loads(subprocess.check_output(['docker', 'inspect', 'buildx_buildkit_' + node]))[0]
        verify.require(container['Config']['Image'] == BUILDKIT and container['State']['Running'], 'builder image drift')
        command = ['docker', 'buildx', 'build', '--platform=linux/amd64', '--network=none',
                   '--provenance=mode=max', '--sbom=true', '--progress=plain',
                   '--build-arg=REVISION=' + revision, '--build-arg=SOURCE_DATE_EPOCH=' + str(epoch),
                   '--output=type=oci,dest=' + str(archive) + ',rewrite-timestamp=true',
                   '--file=' + str(HERE / 'extension.Dockerfile'), str(HERE)]
        if args.no_cache:
            command.append('--no-cache')
        (output / 'build-context.json').write_text(json.dumps({
            'revision': revision, 'source_epoch': epoch, 'no_cache': args.no_cache,
            'command': command}, indent=2))
        with (output / 'build.log').open('x') as log:
            result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=600)
        if result.returncode:
            print((output / 'build.log').read_text()[-5000:], file=sys.stderr)
        result.check_returncode()
    receipt, files = verify.inspect(archive, revision, epoch)
    receipt['archive_sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
    verify.require(git('rev-parse', 'HEAD') == revision and not git('status', '--porcelain'), 'source changed')
    if args.mode != 'publish':
        with (output / (args.mode + '-receipt.json')).open('x') as stream:
            json.dump(receipt, stream, indent=2)
        print(json.dumps(receipt, indent=2))
        return
    recorded = json.loads((output / 'build-receipt.json').read_text())
    verify.require(recorded == receipt, 'build receipt differs from inspected archive')
    image = 'ghcr.io/noeljackson/drbd'
    reference = image + ':9.3.3-v1.14.0-wg-' + revision
    with tempfile.TemporaryDirectory(prefix='drbd-publish-') as temp:
        temp = Path(temp)
        existing = subprocess.run(['skopeo', 'inspect', '--raw', 'docker://' + reference], capture_output=True, timeout=60)
        if existing.returncode == 0:
            # Retain an existing index only after verifying its complete payload,
            # subject chain and source identity, including unchanged module bytes.
            old = temp / 'existing.oci.tar'
            subprocess.run(['skopeo', 'copy', '--all', '--preserve-digests', 'docker://' + reference,
                            'oci-archive:' + str(old)], check=True, timeout=180)
            prior, _ = verify.inspect(old, revision, epoch)
            verify.require(prior['platform_manifest'] == receipt['platform_manifest'], 'immutable payload collision')
            receipt['built_index'] = receipt['index']
            receipt['index'] = prior['index']
            receipt['publication'] = 'reused'
        else:
            error = existing.stderr.decode(errors='replace').lower()
            verify.require(any(s in error for s in ('manifest unknown', 'manifest_unknown', 'name unknown', 'name_unknown')), 'could not prove tag absent')
            layout = temp / 'layout'
            verify.materialize(files, layout)
            subprocess.run(['skopeo', 'copy', '--all', '--preserve-digests', '--src-no-creds',
                            'oci:' + str(layout), 'docker://' + reference], check=True, timeout=180)
            receipt['publication'] = 'published'
        remote = subprocess.check_output(['skopeo', 'inspect', '--raw', 'docker://' + reference], timeout=60)
        verify.require(verify.digest(remote) == receipt['index'], 'remote index differs')
    receipt['reference'] = reference + '@' + receipt['index']
    with (output / 'publication.json').open('x') as stream:
        json.dump(receipt, stream, indent=2)
    with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
        stream.write('image=' + image + '\ndigest=' + receipt['index'] + '\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
