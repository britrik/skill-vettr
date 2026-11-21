import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { checkRedirectTarget, isPublicAddress, resolvePublicHost, downloadPublicHttps } from '../utils/safe-fetch.js';

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
