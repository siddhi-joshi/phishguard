# PhishGuard

PhishGuard is a small Chrome extension that checks web addresses for common phishing indicators. It combines URL analysis with a small set of signals from the page currently open in the active tab.

It is designed to give a fast, understandable warning before a user enters a password, payment detail, or other sensitive information.

## What it checks

PhishGuard looks for several independent warning signs and combines them into a risk score:

- Brand impersonation, including domains such as `paypal.example.com` and look-alikes such as `paypa1`.
- Suspicious authentication and account-related words in the host, path, and query string.
- Raw IP addresses used as websites.
- HTTP pages that do not use encryption.
- Internationalized look-alike domains using `xn--` names.
- URL credentials, unusual ports, excessive subdomains, repeated hyphens, and very long URLs.
- Shortened links whose final destination is hidden.
- Encoded URL content and redirect parameters that can conceal a destination.
- Password forms that submit data to a different registered domain.
- Hidden frames when a page also contains password fields.

The analyzer uses domain boundaries and common country-code suffixes to reduce false positives. For example, a real Microsoft subdomain is treated differently from a domain that merely contains the word `microsoft`.

## Risk levels

| Score | Verdict | Meaning |
| --- | --- | --- |
| 0-24 | Safe | No common phishing indicators were found. This is not a guarantee that the site is trustworthy. |
| 25-54 | Suspicious | One or more meaningful warning signs were found. Avoid entering sensitive information until the site is verified. |
| 55-100 | Dangerous | Multiple indicators, or a high-confidence phishing pattern, were found. Leave the page and do not sign in. |

The popup displays the score and the individual reasons that contributed to it. The toolbar badge uses `?` for suspicious pages and `!` for dangerous pages.

## Install locally

PhishGuard is currently distributed as an unpacked development extension.

1. Open Chrome and go to `chrome://extensions`.
2. Turn on **Developer mode**.
3. Select **Load unpacked**.
4. Choose the `phishguard` folder.
5. Pin PhishGuard to the toolbar if you want quick access to its badge and popup.

After changing source files, return to `chrome://extensions` and select **Reload** on the PhishGuard card.

## Use it

When a tab finishes loading, the background service worker checks its URL and updates the toolbar badge when appropriate.

Open the extension popup to:

- Review the current page's verdict and score.
- See the reasons behind the score.
- Include page-level signals such as password fields, form destinations, and hidden frames.
- Check another HTTP or HTTPS URL manually.

Chrome restricts scripts on some pages, including browser-internal pages and extension stores. On those pages, PhishGuard falls back to URL-only analysis or skips the page.

## Test the analyzer

The analyzer has a dependency-free Node.js test file covering first-party login pages, brand impersonation, look-alike domains, raw IP addresses, encoded redirects, off-site password forms, and false-positive cases.

From the workspace root, run:

```text
node phishguard/analyzer.test.js
```

The JavaScript files can also be syntax-checked with:

```text
node --check phishguard/analyzer.js
node --check phishguard/popup.js
node --check phishguard/background.js
```

## Privacy and security

PhishGuard does not send URLs or page contents to a remote service. Analysis runs locally in the extension using the address and limited page signals collected when the popup is opened.

The extension does not attempt to log in, submit forms, change page contents, or block navigation. It provides a warning only. Treat a safe result as an absence of known indicators, not as proof that a website is legitimate.

## Limitations

PhishGuard is a local heuristic detector, not a complete threat-intelligence service. It may miss newly created phishing domains, compromised legitimate sites, malicious downloads, and attacks that do not expose clear URL or form indicators. It also cannot confirm who owns a domain or whether a page's content is safe.

For high-risk actions, verify the address independently, use a bookmark or a trusted application, and do not rely on a browser warning alone.

## Project files

- `manifest.json` defines the Chrome extension and its permissions.
- `analyzer.js` contains the shared URL and page-signal scoring logic.
- `background.js` updates the toolbar badge for open tabs.
- `popup.html`, `popup.css`, and `popup.js` implement the user interface.
- `analyzer.test.js` contains the analyzer regression tests.
- `icons/` contains the extension icons.
