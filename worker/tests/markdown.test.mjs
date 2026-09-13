import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<div id="content"></div>');
globalThis.window = dom.window;
globalThis.document = dom.window.document;
const { renderMarkdown, validateOverview } = await import('../../ui/markdown.js');
const content = document.querySelector('#content');

test('Markdown renders headings, tables, code and safe links', () => {
  renderMarkdown('# Hello\n\n| Name | Type |\n| --- | --- |\n| cli | component |\n\n```sh\nwasmd pull demo/hello:1.0.0\n```\n\n[Docs](https://example.com)\n\n![Logo](https://example.com/logo.png)', content);
  assert.equal(content.querySelector('h1').textContent, 'Hello');
  assert.equal(content.querySelectorAll('td').length, 2);
  assert.match(content.querySelector('pre code').textContent, /wasmd pull/);
  assert.equal(content.querySelector('a').getAttribute('rel'), 'nofollow noopener noreferrer');
  assert.equal(content.querySelector('img').getAttribute('referrerpolicy'), 'no-referrer');
});

test('Markdown strips executable content, clobbering, styling and unsafe URLs', () => {
  renderMarkdown('<script>alert(1)</script><img src="x" onerror="alert(1)"><svg onload="alert(1)"></svg>\n\n[x](javascript:alert%281%29)\n\n<a id="edit-overview" name="location" style="position:fixed" href="/v1/auth/github">internal</a><iframe src="https://evil.test"></iframe><form action="https://evil.test"><input name="password"></form><img src="data:image/svg+xml,evil">\n\n[relative](./docs.md)', content);
  assert.equal(content.querySelector('script,svg,iframe,form,input,[id],[name],[style],[onerror],[onload],img'), null);
  assert.equal(content.querySelector('a[href]'), null);
});

test('Overview enforces UTF-8 size and renders an explicit empty state', () => {
  assert.throws(() => validateOverview('界'.repeat(21846)), /64 KiB/);
  assert.equal(validateOverview('a'.repeat(65536)).length, 65536);
  renderMarkdown('', content);
  assert.match(content.textContent, /No overview yet/);
});
