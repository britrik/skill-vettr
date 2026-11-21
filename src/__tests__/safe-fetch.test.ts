import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { assertGitSupportsResolvePin, assertTreeWithinLimit, checkRedirectTarget, gitResolvePin, gunzipCapped, isPublicAddress, resolvePublicHost, downloadPublicHttps } from '../utils/safe-fetch.js';

describe('isPublicAddress', () => {
  it('rejects loopback, private, link-local and metadata addresses', () => {
    for (const ip of [
      '127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254',
      '100.64.0.1', '0.0.0.0', '224.0.0.1', '::1', '::', 'fe80::1', 'fc00::1',
      '::ffff:127.0.0.1', '2001:db8::1',
    ]) {
      assert.equal(isPublicAddress(ip), false, ip);
    }
  });

  it('accepts public unicast addresses', () => {
    for (const ip of ['93.184.216.34', '140.82.112.3', '2606:4700::6810:84e5']) {
      assert.equal(isPublicAddress(ip), true, ip);
    }
  });

  it('rejects non-IP strings', () => {
    assert.equal(isPublicAddress('example.com'), false);
  });
});

describe('resolvePublicHost', () => {
  it('fails when any resolved address is internal', async () => {
    await assert.rejects(
      resolvePublicHost('rebind.example.com', async () => ['93.184.216.34', '127.0.0.1']),
      /non-public/,
    );
  });

  it('rejects IP-literal hosts', async () => {
    await assert.rejects(resolvePublicHost('169.254.169.254', async () => ['169.254.169.254']), /IP-literal/);
  });

  it('returns addresses for public hosts', async () => {
    assert.deepEqual(await resolvePublicHost('example.com', async () => ['93.184.216.34']), ['93.184.216.34']);
  });
});

describe('downloadPublicHttps', () => {
  it('refuses to connect when the host resolves to an internal address', async () => {
    await assert.rejects(
      downloadPublicHttps('https://internal.example.com/skill.tar.gz', path.join(os.tmpdir(), 'unused.tar.gz'), {
        resolver: async () => ['10.0.0.5'],
      }),
      /non-public/,
    );
  });

  it('rejects non-HTTPS URLs before any lookup', async () => {
    await assert.rejects(
      downloadPublicHttps('http://example.com/skill.tar.gz', path.join(os.tmpdir(), 'unused.tar.gz'), {
        resolver: async () => {
          throw new Error('resolver should not be called');
        },
      }),
      /Invalid URL format/,
    );
  });
});


describe('checkRedirectTarget', () => {
  it('accepts signed HTTPS download URLs with query strings', () => {
    const url = 'https://objects.example.com/archive.tar.gz?X-Amz-Signature=abc&X-Amz-Expires=300';
    assert.equal(checkRedirectTarget(url), url);
  });

  it('rejects downgrade, credentials and non-default ports', () => {
    assert.throws(() => checkRedirectTarget('http://example.com/a.tgz'), /HTTPS/);
    assert.throws(() => checkRedirectTarget('https://user:pw@example.com/a.tgz'), /credentials/);
    assert.throws(() => checkRedirectTarget('https://example.com:8443/a.tgz'), /port/);
  });
});

describe('gitResolvePin', () => {
  it('pins the host to every validated IPv4 address on port 443, preferring IPv4', () => {
    assert.equal(
      gitResolvePin('example.com', ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946', '93.184.216.35']),
      'example.com:443:93.184.216.34,93.184.216.35',
    );
  });

  it('brackets IPv6 addresses when the host has no IPv4 address', () => {
    assert.equal(
      gitResolvePin('example.com', ['2606:2800:220:1:248:1893:25c8:1946']),
      'example.com:443:[2606:2800:220:1:248:1893:25c8:1946]',
    );
  });

  it('refuses an empty or non-public address list', () => {
    assert.throws(() => gitResolvePin('example.com', []), /non-public or empty/);
    assert.throws(() => gitResolvePin('example.com', ['93.184.216.34', '10.0.0.1']), /non-public or empty/);
  });
});

describe('assertGitSupportsResolvePin', () => {
  it('accepts git 2.37 and later', () => {
    for (const v of ['git version 2.37.0', 'git version 2.53.0\n', 'git version 3.0.1', 'git version 2.39.5 (Apple Git-154)']) {
      assert.doesNotThrow(() => assertGitSupportsResolvePin(v), v);
    }
  });

  it('refuses older or unrecognised git versions', () => {
    assert.throws(() => assertGitSupportsResolvePin('git version 2.36.6'), /ignores http.curloptResolve/);
    assert.throws(() => assertGitSupportsResolvePin('git version 1.9.1'), /ignores http.curloptResolve/);
    assert.throws(() => assertGitSupportsResolvePin('something else'), /Could not determine/);
  });
});

describe('gunzipCapped', () => {
  it('decompresses within the limit and refuses archives that expand past it', async () => {
    const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'vettr-gz-'));
    try {
      const gz = path.join(dir, 'a.gz');
      await fs.promises.writeFile(gz, zlib.gzipSync(Buffer.alloc(64 * 1024)));
      await gunzipCapped(gz, path.join(dir, 'ok.tar'), 128 * 1024);
      assert.equal((await fs.promises.stat(path.join(dir, 'ok.tar'))).size, 64 * 1024);
      await assert.rejects(gunzipCapped(gz, path.join(dir, 'big.tar'), 16 * 1024), /expands to more than/);
      assert.equal(fs.existsSync(path.join(dir, 'big.tar')), false);
    } finally {
      await fs.promises.rm(dir, { recursive: true, force: true });
    }
  });
});

describe('assertTreeWithinLimit', () => {
  it('refuses a tar whose sparse member declares more than the limit', async () => {
    const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'vettr-sparse-'));
    try {
      const src = path.join(dir, 'src');
      const out = path.join(dir, 'out');
      await fs.promises.mkdir(src);
      await fs.promises.mkdir(out);
      await fs.promises.writeFile(path.join(src, 'SKILL.md'), '# skill\n');
      const handle = await fs.promises.open(path.join(src, 'hole.bin'), 'w');
      await handle.truncate(64 * 1024 * 1024);
      await handle.close();
      const tar = path.join(dir, 'sparse.tar');
      execFileSync('tar', ['-cSf', tar, '-C', src, '.']);
      assert.ok((await fs.promises.stat(tar)).size < 1024 * 1024, 'fixture tar should be small');
      execFileSync('tar', ['-xf', tar, '-C', out]);
      await assert.rejects(assertTreeWithinLimit(out, 16 * 1024 * 1024), /larger than/);
      await assertTreeWithinLimit(out, 128 * 1024 * 1024);
    } finally {
      await fs.promises.rm(dir, { recursive: true, force: true });
    }
  });
});
