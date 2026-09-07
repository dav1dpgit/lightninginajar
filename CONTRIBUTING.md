# Contributing

Thank you for looking. A few things to know before you spend time.

**Issues are welcome.** A clear report — what you did, what you expected, what happened, the wallet's version string (Menu → the Build row) — is the most useful thing a reader can give this project. Security findings go through [SECURITY.md](SECURITY.md), not the issue tracker.

**Talk before a pull request.** This wallet moves money; every change to the engine, the page, the adapter or the registry is discussed and decided before it is written, and shipped as a versioned build with its own gate. A pull request that arrives without that conversation will most likely be closed with a pointer to this file, however good it is. Open an issue that says what you want to change and why; if it fits, we will agree the shape and you can build it.

**What is easy to take:** documentation fixes, test cases, reproductions of bugs, and reviews of [docs/ldk-patches.md](docs/ldk-patches.md) — the LDK patch set has had no independent review yet and that is the single most valuable thing an outside reader can do.

**What this repository is not:** a supported product. There is one developer, no release schedule, no promise that an issue will be answered on any timeline, and no warranty (see [LICENSE](LICENSE)). The live wallet at lightninginajar.xyz is a pre-release; its README says what that means for your funds.

**History.** This public repository starts from a clean first commit. The private development history is not published; design records that survived the cut are in `docs/`.

**License.** By contributing you agree your contribution is licensed under the repository's MIT license.
