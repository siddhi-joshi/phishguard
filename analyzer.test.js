'use strict';

const assert = require('node:assert/strict');
const { analyze, registeredDomain } = require('./analyzer.js');

function verdict(url, page) { return analyze(url, page).verdict; }

// Domain parsing must keep the registrable part, including common country-code suffixes.
assert.equal(registeredDomain('login.accounts.example.co.uk'), 'example.co.uk');
assert.equal(registeredDomain('WWW.Example.COM.'), 'example.com');

// First-party URLs with ordinary authentication paths are not phishing by themselves.
assert.equal(verdict('https://login.microsoftonline.com/common/oauth2/authorize'), 'safe');
assert.equal(verdict('https://www.paypal.com/signin'), 'safe');
assert.equal(verdict('https://example.com/article-about-accounting'), 'safe');

// Brand impersonation and look-alike domains should be high-confidence detections.
assert.equal(verdict('https://paypal.example.net/login'), 'dangerous');
assert.equal(verdict('https://paypa1-login.example/verify'), 'dangerous');
assert.equal(verdict('https://example.net/paypal.com/verify'), 'suspicious');

// Infrastructure and obfuscation signals should combine with page evidence.
assert.equal(verdict('http://203.0.113.42/login'), 'dangerous');
assert.equal(verdict('http://example.com/login', {
  passwordFields: 1,
  formHosts: ['collector.example.net'],
  hiddenIframes: 1
}), 'dangerous');

// Common words inside larger words should not trigger a false positive.
assert.equal(verdict('https://example.com/accounting/securely-updateable'), 'safe');

console.log('PhishGuard analyzer tests passed.');
