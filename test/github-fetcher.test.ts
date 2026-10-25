import { describe, it, expect, vi } from 'vitest';
import { parseGitHubRepoUrl, fetchRawGitHubFile, fetchRepositoryManifests, GitHubFetcherError } from '../src/server/github-fetcher.js';

describe('GitHub Fetcher', () => {
  describe('parseGitHubRepoUrl', () => {
    it('parses "owner/repo" correctly', () => {
      const res = parseGitHubRepoUrl('expressjs/express');
      expect(res.owner).toBe('expressjs');
      expect(res.repo).toBe('express');
      expect(res.branch).toBeUndefined();
    });

    it('parses full https://github.com/owner/repo URL', () => {
      const res = parseGitHubRepoUrl('https://github.com/pallets/flask');
      expect(res.owner).toBe('pallets');
      expect(res.repo).toBe('flask');
    });

    it('parses URL with .git extension', () => {
      const res = parseGitHubRepoUrl('https://github.com/psf/requests.git');
      expect(res.owner).toBe('psf');
      expect(res.repo).toBe('requests');
    });

    it('parses URL with branch in /tree/branch path', () => {
      const res = parseGitHubRepoUrl('https://github.com/facebook/react/tree/main');
      expect(res.owner).toBe('facebook');
      expect(res.repo).toBe('react');
      expect(res.branch).toBe('main');
    });

    it('rejects invalid hosts', () => {
      expect(() => parseGitHubRepoUrl('https://gitlab.com/owner/repo')).toThrow('Only public GitHub repositories are supported');
    });

    it('rejects path traversal or malicious inputs', () => {
      expect(() => parseGitHubRepoUrl('../../../etc/passwd')).toThrow();
      expect(() => parseGitHubRepoUrl('owner/..')).toThrow();
    });

    it('rejects empty or whitespace input', () => {
      expect(() => parseGitHubRepoUrl('')).toThrow('Repository URL or "owner/repo" string is required.');
    });
  });

  describe('fetchRawGitHubFile', () => {
    it('returns null on 404', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        status: 404,
        ok: false,
        headers: new Headers()
      });

      const content = await fetchRawGitHubFile('owner', 'repo', 'package.json', 'HEAD', mockFetch as any);
      expect(content).toBeNull();
    });

    it('throws on 429 rate limit', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        status: 429,
        ok: false,
        headers: new Headers()
      });

      await expect(
        fetchRawGitHubFile('owner', 'repo', 'package.json', 'HEAD', mockFetch as any)
      ).rejects.toThrow('rate limit reached');
    });

    it('returns file content on 200', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        headers: new Headers({ 'content-length': '15' }),
        text: () => Promise.resolve('{"name":"test"}')
      });

      const content = await fetchRawGitHubFile('owner', 'repo', 'package.json', 'HEAD', mockFetch as any);
      expect(content).toBe('{"name":"test"}');
    });

    it('throws if file size exceeds 5MB', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        headers: new Headers({ 'content-length': String(6 * 1024 * 1024) }),
        text: () => Promise.resolve('')
      });

      await expect(
        fetchRawGitHubFile('owner', 'repo', 'requirements.txt', 'HEAD', mockFetch as any)
      ).rejects.toThrow('exceeds the maximum allowed size of 5 MB');
    });

    it('rejects requests for non-manifest files before making a network request', async () => {
      const mockFetch = vi.fn();
      await expect(
        fetchRawGitHubFile('owner', 'repo', 'src/index.ts', 'HEAD', mockFetch as any)
      ).rejects.toThrow('Invalid repository manifest request');
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('does not follow redirects from raw GitHub', async () => {
      const mockFetch = vi.fn().mockRejectedValue(new TypeError('redirect disallowed'));
      await expect(
        fetchRawGitHubFile('owner', 'repo', 'package.json', 'HEAD', mockFetch as any)
      ).rejects.toThrow('Network error fetching "package.json"');
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('raw.githubusercontent.com'),
        expect.objectContaining({ redirect: 'error' })
      );
    });
  });

  describe('fetchRepositoryManifests', () => {
    it('discovers npm manifests successfully', async () => {
      const mockFetch = vi.fn().mockImplementation((url: string) => {
        if (url.includes('package-lock.json')) {
          return Promise.resolve({
            status: 200,
            ok: true,
            headers: new Headers(),
            text: () => Promise.resolve('{"name":"my-app","lockfileVersion":3,"packages":{}}')
          });
        }
        if (url.includes('package.json')) {
          return Promise.resolve({
            status: 200,
            ok: true,
            headers: new Headers(),
            text: () => Promise.resolve('{"name":"my-app","version":"1.0.0"}')
          });
        }
        return Promise.resolve({
          status: 404,
          ok: false,
          headers: new Headers()
        });
      });

      const res = await fetchRepositoryManifests('my-org/my-app', mockFetch as any);
      expect(res.ecosystem).toBe('npm');
      expect(res.foundFiles).toContain('package-lock.json');
      expect(res.foundFiles).toContain('package.json');
      expect(res.manifestContents.packageLockJson).toBeDefined();
    });

    it('discovers python requirements.txt manifests successfully', async () => {
      const mockFetch = vi.fn().mockImplementation((url: string) => {
        if (url.includes('requirements.txt')) {
          return Promise.resolve({
            status: 200,
            ok: true,
            headers: new Headers(),
            text: () => Promise.resolve('requests==2.28.1\nflask==2.2.2\n')
          });
        }
        return Promise.resolve({
          status: 404,
          ok: false,
          headers: new Headers()
        });
      });

      const res = await fetchRepositoryManifests('pallets/flask', mockFetch as any);
      expect(res.ecosystem).toBe('pypi');
      expect(res.foundFiles).toEqual(['requirements.txt']);
      expect(res.manifestContents.requirementsTxt).toBeDefined();
    });

    it('throws descriptive error if no supported manifests are found', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        status: 404,
        ok: false,
        headers: new Headers()
      });

      await expect(
        fetchRepositoryManifests('empty/repo', mockFetch as any)
      ).rejects.toThrow('No supported dependency manifests found');
    });
  });
});
