# Security policy

Glessner is a pre-alpha project with one maintainer. Report a security problem privately through GitHub's private vulnerability reporting. Don't open a public issue for it.

## Supported versions

Only the current state of the main branch is supported. No release has a separate support period.

## What to report

Report a way to cross one of the boundaries the README states:

- The app writes into the evidence folder.
- The app makes a network call.
- Another program or web page on the same machine drives the local server without its session token.
- A crafted evidence file or log runs code, or runs script in the page.
- A CSV export that a spreadsheet runs as a formula.
- The app runs an executable from the evidence folder or the case folder, in place of the tools folder or `PATH`.

These are not security problems in Glessner:

- A flaw in a tool that Glessner runs, such as EvtxECmd, Hayabusa, or Suricata. Report it to that tool's publisher, who is named in the README's [Licenses and credits](README.md#licenses-and-credits).
- A change made by someone who can already write to the case folder. The journal's hash chain shows such a change only against a head you recorded outside the case. [known_limitations.md](known_limitations.md) says so.

## How to report

1. Open the repository on GitHub and select the **Security and quality** tab.
2. Select **Report a vulnerability**.
3. Fill in the form. By default it asks for a summary, details, a proof of concept, and the impact.

Use a small synthetic file as the proof of concept. Don't attach evidence, case files, or real incident data.

If the **Report a vulnerability** button isn't there, private reporting isn't enabled yet. Open an issue that asks for a private security contact, and put no details in it.

## What to expect

Glessner has one maintainer and no fixed response time. The maintainer replies in the advisory thread. A confirmed problem is fixed on the main branch and noted in [CHANGELOG.md](CHANGELOG.md).
