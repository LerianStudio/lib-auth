## [3.5.0](https://github.com/LerianStudio/lib-auth/compare/v3.4.0...v3.5.0) (2026-08-27)


### Features

* **declaration:** add WireFromEnv to hoist plugin D7 boilerplate ([7ef812e](https://github.com/LerianStudio/lib-auth/commit/7ef812e4a3d9ec0064984134937a239c3d4705e9))
* **middleware:** dynamic JWKS key source for M2M token verification ([9e252e1](https://github.com/LerianStudio/lib-auth/commit/9e252e1dcb5cff02ee028f0de5e7ad9b5d5c3155))
* **declaration:** namespace RI/D7 env contract under IDP_ prefix ([#4232](https://github.com/LerianStudio/lib-auth/issues/4232)) ([3e1cdf7](https://github.com/LerianStudio/lib-auth/commit/3e1cdf772a6820bcaada0d099b326de2690f21d4))
* **declaration:** reject HTTP-verb actions in manifest validation ([6ce4f5a](https://github.com/LerianStudio/lib-auth/commit/6ce4f5a0c99bf6ea94fb7a1607e52b1a893bc73b))
* **declaration:** remove HTTP-verb action reject from manifest validation ([c4b590d](https://github.com/LerianStudio/lib-auth/commit/c4b590dce3ee77ce93e537986e7f93c69fa1b2d1)), closes [#143](https://github.com/LerianStudio/lib-auth/issues/143)


### Bug Fixes

* **middleware:** address JWKS review — https fail-closed, ctx detach, bounds ([25ef0e0](https://github.com/LerianStudio/lib-auth/commit/25ef0e09ea927857961b6713fbe0ac4f612de13f))
* **middleware:** address review comments on test goroutine safety and README version note ([85e9d71](https://github.com/LerianStudio/lib-auth/commit/85e9d71301d2bcd231fe5a890ef4c62cccddcbbe))
* **middleware:** bind decision-cache entries to the bearer token ([#147](https://github.com/LerianStudio/lib-auth/issues/147)) ([c7f8460](https://github.com/LerianStudio/lib-auth/commit/c7f84601e856a78caa22348268cdebe3304b6149)), closes [#146](https://github.com/LerianStudio/lib-auth/issues/146)
* **middleware:** cap JWKS redirect hops ([163d728](https://github.com/LerianStudio/lib-auth/commit/163d7288ed7577e4eb3b645c41d9c62c59043fff)), closes [#144](https://github.com/LerianStudio/lib-auth/issues/144)
* **middleware:** inherit the request context instead of extracting inbound trace headers ([#148](https://github.com/LerianStudio/lib-auth/issues/148)) ([0e3da25](https://github.com/LerianStudio/lib-auth/commit/0e3da251fa4356d1850bb9c96e43dd1e51b6816b))
* **middleware:** inherit the request context instead of extracting inbound trace headers ([9a1a05a](https://github.com/LerianStudio/lib-auth/commit/9a1a05a5a1d1ab4facb2722a87e1bb8ccb89633e))
* **middleware:** JWKS review round 2 — redirect policy, host check, atomic cooldown ([ba9c026](https://github.com/LerianStudio/lib-auth/commit/ba9c02693b3a8c961c8440e23a053e92333ac69f))
* **auth:** let concurrent forced JWKS refreshes join the in-flight fetch ([d370ec3](https://github.com/LerianStudio/lib-auth/commit/d370ec3fb51848bf57be3982d7f1d38dad6a82ba)), closes [#152](https://github.com/LerianStudio/lib-auth/issues/152)
* **declaration:** suppress G101 env-name false positive, align identity env doc, harden trim test ([088aa2e](https://github.com/LerianStudio/lib-auth/commit/088aa2e79bb44a57e861b52768d0281424062af5))
* **declaration:** use gosec hash-form nosec directive to suppress G101 ([40ee028](https://github.com/LerianStudio/lib-auth/commit/40ee0289db1267f8b1c281cfeba2cb0ac319a5c8))

## [3.5.0-beta.4](https://github.com/LerianStudio/lib-auth/compare/v3.5.0-beta.3...v3.5.0-beta.4) (2026-08-27)


### Bug Fixes

* **auth:** let concurrent forced JWKS refreshes join the in-flight fetch ([d370ec3](https://github.com/LerianStudio/lib-auth/commit/d370ec3fb51848bf57be3982d7f1d38dad6a82ba)), closes [#152](https://github.com/LerianStudio/lib-auth/issues/152)

## [3.5.0-beta.3](https://github.com/LerianStudio/lib-auth/compare/v3.5.0-beta.2...v3.5.0-beta.3) (2026-08-26)

## [3.5.0-beta.2](https://github.com/LerianStudio/lib-auth/compare/v3.5.0-beta.1...v3.5.0-beta.2) (2026-08-26)

## [3.5.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v3.4.0...v3.5.0-beta.1) (2026-08-23)


### Features

* **declaration:** add WireFromEnv to hoist plugin D7 boilerplate ([7ef812e](https://github.com/LerianStudio/lib-auth/commit/7ef812e4a3d9ec0064984134937a239c3d4705e9))
* **middleware:** dynamic JWKS key source for M2M token verification ([9e252e1](https://github.com/LerianStudio/lib-auth/commit/9e252e1dcb5cff02ee028f0de5e7ad9b5d5c3155))
* **declaration:** namespace RI/D7 env contract under IDP_ prefix ([#4232](https://github.com/LerianStudio/lib-auth/issues/4232)) ([3e1cdf7](https://github.com/LerianStudio/lib-auth/commit/3e1cdf772a6820bcaada0d099b326de2690f21d4))
* **declaration:** reject HTTP-verb actions in manifest validation ([6ce4f5a](https://github.com/LerianStudio/lib-auth/commit/6ce4f5a0c99bf6ea94fb7a1607e52b1a893bc73b))
* **declaration:** remove HTTP-verb action reject from manifest validation ([c4b590d](https://github.com/LerianStudio/lib-auth/commit/c4b590dce3ee77ce93e537986e7f93c69fa1b2d1)), closes [#143](https://github.com/LerianStudio/lib-auth/issues/143)


### Bug Fixes

* **middleware:** address JWKS review — https fail-closed, ctx detach, bounds ([25ef0e0](https://github.com/LerianStudio/lib-auth/commit/25ef0e09ea927857961b6713fbe0ac4f612de13f))
* **middleware:** address review comments on test goroutine safety and README version note ([85e9d71](https://github.com/LerianStudio/lib-auth/commit/85e9d71301d2bcd231fe5a890ef4c62cccddcbbe))
* **middleware:** bind decision-cache entries to the bearer token ([#147](https://github.com/LerianStudio/lib-auth/issues/147)) ([c7f8460](https://github.com/LerianStudio/lib-auth/commit/c7f84601e856a78caa22348268cdebe3304b6149)), closes [#146](https://github.com/LerianStudio/lib-auth/issues/146)
* **middleware:** cap JWKS redirect hops ([163d728](https://github.com/LerianStudio/lib-auth/commit/163d7288ed7577e4eb3b645c41d9c62c59043fff)), closes [#144](https://github.com/LerianStudio/lib-auth/issues/144)
* **middleware:** inherit the request context instead of extracting inbound trace headers ([#148](https://github.com/LerianStudio/lib-auth/issues/148)) ([0e3da25](https://github.com/LerianStudio/lib-auth/commit/0e3da251fa4356d1850bb9c96e43dd1e51b6816b))
* **middleware:** inherit the request context instead of extracting inbound trace headers ([9a1a05a](https://github.com/LerianStudio/lib-auth/commit/9a1a05a5a1d1ab4facb2722a87e1bb8ccb89633e))
* **middleware:** JWKS review round 2 — redirect policy, host check, atomic cooldown ([ba9c026](https://github.com/LerianStudio/lib-auth/commit/ba9c02693b3a8c961c8440e23a053e92333ac69f))
* **declaration:** suppress G101 env-name false positive, align identity env doc, harden trim test ([088aa2e](https://github.com/LerianStudio/lib-auth/commit/088aa2e79bb44a57e861b52768d0281424062af5))
* **declaration:** use gosec hash-form nosec directive to suppress G101 ([40ee028](https://github.com/LerianStudio/lib-auth/commit/40ee0289db1267f8b1c281cfeba2cb0ac319a5c8))

## [3.4.0](https://github.com/LerianStudio/lib-auth/compare/v3.3.0...v3.4.0) (2026-08-23)


### Bug Fixes

* **middleware:** derive the client IP inside the library ([5e7b1bb](https://github.com/LerianStudio/lib-auth/commit/5e7b1bbc3d9bdd654eeba3de50a5fe1bb881b4c9))
* **middleware:** name the rule that rejected a trusted-proxy entry ([792f1f3](https://github.com/LerianStudio/lib-auth/commit/792f1f3bf61e9d2f4392a3c412f05d2f4e8d10fd))
* **middleware:** read the forwarded chain from the request, not c.IPs() ([b32e95b](https://github.com/LerianStudio/lib-auth/commit/b32e95befcd1f23312cf23ad22a34e1c8b66d814))
* **middleware:** rebase v4-mapped trusted-proxy ranges to IPv4 ([1fc3e0f](https://github.com/LerianStudio/lib-auth/commit/1fc3e0f5cc26e04ec9afc507d74661df3c632892))
* **middleware:** suggest a zoned-address correction that parses ([16d09c5](https://github.com/LerianStudio/lib-auth/commit/16d09c5d0ee63b55a1dc4a027a9bf2a71f1ea8a0))
* **middleware:** validate a suggested correction before printing it ([efea2c6](https://github.com/LerianStudio/lib-auth/commit/efea2c6f9556d203bfb3146502f7e0e6260a1983))

## [3.4.0-beta.6](https://github.com/LerianStudio/lib-auth/compare/v3.4.0-beta.5...v3.4.0-beta.6) (2026-08-19)


### Features

* **declaration:** namespace RI/D7 env contract under IDP_ prefix ([#4232](https://github.com/LerianStudio/lib-auth/issues/4232)) ([3e1cdf7](https://github.com/LerianStudio/lib-auth/commit/3e1cdf772a6820bcaada0d099b326de2690f21d4))

## [3.4.0-beta.5](https://github.com/LerianStudio/lib-auth/compare/v3.4.0-beta.4...v3.4.0-beta.5) (2026-08-18)


### Bug Fixes

* **middleware:** address review comments on test goroutine safety and README version note ([85e9d71](https://github.com/LerianStudio/lib-auth/commit/85e9d71301d2bcd231fe5a890ef4c62cccddcbbe))
* **middleware:** inherit the request context instead of extracting inbound trace headers ([#148](https://github.com/LerianStudio/lib-auth/issues/148)) ([0e3da25](https://github.com/LerianStudio/lib-auth/commit/0e3da251fa4356d1850bb9c96e43dd1e51b6816b))
* **middleware:** inherit the request context instead of extracting inbound trace headers ([9a1a05a](https://github.com/LerianStudio/lib-auth/commit/9a1a05a5a1d1ab4facb2722a87e1bb8ccb89633e))

## [3.4.0-beta.4](https://github.com/LerianStudio/lib-auth/compare/v3.4.0-beta.3...v3.4.0-beta.4) (2026-08-08)


### Bug Fixes

* **middleware:** bind decision-cache entries to the bearer token ([#147](https://github.com/LerianStudio/lib-auth/issues/147)) ([c7f8460](https://github.com/LerianStudio/lib-auth/commit/c7f84601e856a78caa22348268cdebe3304b6149)), closes [#146](https://github.com/LerianStudio/lib-auth/issues/146)

## [3.4.0-beta.3](https://github.com/LerianStudio/lib-auth/compare/v3.4.0-beta.2...v3.4.0-beta.3) (2026-08-07)


### Features

* **middleware:** dynamic JWKS key source for M2M token verification ([9e252e1](https://github.com/LerianStudio/lib-auth/commit/9e252e1dcb5cff02ee028f0de5e7ad9b5d5c3155))
* **declaration:** remove HTTP-verb action reject from manifest validation ([c4b590d](https://github.com/LerianStudio/lib-auth/commit/c4b590dce3ee77ce93e537986e7f93c69fa1b2d1)), closes [#143](https://github.com/LerianStudio/lib-auth/issues/143)


### Bug Fixes

* **middleware:** address JWKS review — https fail-closed, ctx detach, bounds ([25ef0e0](https://github.com/LerianStudio/lib-auth/commit/25ef0e09ea927857961b6713fbe0ac4f612de13f))
* **middleware:** cap JWKS redirect hops ([163d728](https://github.com/LerianStudio/lib-auth/commit/163d7288ed7577e4eb3b645c41d9c62c59043fff)), closes [#144](https://github.com/LerianStudio/lib-auth/issues/144)
* **middleware:** JWKS review round 2 — redirect policy, host check, atomic cooldown ([ba9c026](https://github.com/LerianStudio/lib-auth/commit/ba9c02693b3a8c961c8440e23a053e92333ac69f))

## [3.4.0-beta.2](https://github.com/LerianStudio/lib-auth/compare/v3.4.0-beta.1...v3.4.0-beta.2) (2026-08-05)


### Features

* **declaration:** reject HTTP-verb actions in manifest validation ([6ce4f5a](https://github.com/LerianStudio/lib-auth/commit/6ce4f5a0c99bf6ea94fb7a1607e52b1a893bc73b))

## [3.4.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v3.3.1-beta.1...v3.4.0-beta.1) (2026-08-04)


### Features

* **declaration:** add WireFromEnv to hoist plugin D7 boilerplate ([7ef812e](https://github.com/LerianStudio/lib-auth/commit/7ef812e4a3d9ec0064984134937a239c3d4705e9))


### Bug Fixes

* **declaration:** suppress G101 env-name false positive, align identity env doc, harden trim test ([088aa2e](https://github.com/LerianStudio/lib-auth/commit/088aa2e79bb44a57e861b52768d0281424062af5))
* **declaration:** use gosec hash-form nosec directive to suppress G101 ([40ee028](https://github.com/LerianStudio/lib-auth/commit/40ee0289db1267f8b1c281cfeba2cb0ac319a5c8))

## [3.3.1-beta.1](https://github.com/LerianStudio/lib-auth/compare/v3.3.0...v3.3.1-beta.1) (2026-07-30)

## [3.3.0](https://github.com/LerianStudio/lib-auth/compare/v3.2.0...v3.3.0) (2026-07-29)


### Features

* **declaration:** add D7 declaration publisher (startup manifest push) ([766b212](https://github.com/LerianStudio/lib-auth/commit/766b2122af85474724bc19c8ef8968324ee4be51))


### Bug Fixes

* **declaration:** escape slug and normalize identity base URL ([01e933d](https://github.com/LerianStudio/lib-auth/commit/01e933deea689824d70984b170947a2b868644c6)), closes [#138](https://github.com/LerianStudio/lib-auth/issues/138)
* **declaration:** retry token mint and escape slug path segment ([a58998f](https://github.com/LerianStudio/lib-auth/commit/a58998ff6dcd7bf5b488499fc7176605814edb38)), closes [#138](https://github.com/LerianStudio/lib-auth/issues/138)
* **declaration:** validate identity URL and reject dot-segment slug ([7f686ae](https://github.com/LerianStudio/lib-auth/commit/7f686ae3b09ccd80573459b420d8e205331bd0c6)), closes [#138](https://github.com/LerianStudio/lib-auth/issues/138)

## [3.3.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v3.2.0...v3.3.0-beta.1) (2026-07-29)


### Features

* **declaration:** add D7 declaration publisher (startup manifest push) ([766b212](https://github.com/LerianStudio/lib-auth/commit/766b2122af85474724bc19c8ef8968324ee4be51))


### Bug Fixes

* **declaration:** escape slug and normalize identity base URL ([01e933d](https://github.com/LerianStudio/lib-auth/commit/01e933deea689824d70984b170947a2b868644c6)), closes [#138](https://github.com/LerianStudio/lib-auth/issues/138)
* **declaration:** retry token mint and escape slug path segment ([a58998f](https://github.com/LerianStudio/lib-auth/commit/a58998ff6dcd7bf5b488499fc7176605814edb38)), closes [#138](https://github.com/LerianStudio/lib-auth/issues/138)
* **declaration:** validate identity URL and reject dot-segment slug ([7f686ae](https://github.com/LerianStudio/lib-auth/commit/7f686ae3b09ccd80573459b420d8e205331bd0c6)), closes [#138](https://github.com/LerianStudio/lib-auth/issues/138)

## [3.2.0](https://github.com/LerianStudio/lib-auth/compare/v3.1.0...v3.2.0) (2026-07-28)


### Features

* **middleware:** forward client IP to /v1/authorize + scope decision cache by it ([cbee470](https://github.com/LerianStudio/lib-auth/commit/cbee4709d749adee4300bcccc34630c2cd9cc208))


### Bug Fixes

* **middleware:** keep the caller IP out of the tracing span ([c94c21a](https://github.com/LerianStudio/lib-auth/commit/c94c21a14d47688a5314e4e3b79caa0df51fa6ed))

## [3.2.0-beta.2](https://github.com/LerianStudio/lib-auth/compare/v3.2.0-beta.1...v3.2.0-beta.2) (2026-07-28)


### Bug Fixes

* **middleware:** keep the caller IP out of the tracing span ([c94c21a](https://github.com/LerianStudio/lib-auth/commit/c94c21a14d47688a5314e4e3b79caa0df51fa6ed))

## [3.2.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v3.1.0...v3.2.0-beta.1) (2026-07-24)


### Features

* **middleware:** forward client IP to /v1/authorize + scope decision cache by it ([cbee470](https://github.com/LerianStudio/lib-auth/commit/cbee4709d749adee4300bcccc34630c2cd9cc208))

## [3.1.0](https://github.com/LerianStudio/lib-auth/compare/v3.0.0...v3.1.0) (2026-07-24)


### Features

* **middleware:** opt-in flag for M2M inversion ([55c23ee](https://github.com/LerianStudio/lib-auth/commit/55c23eea505c248ea1ce4884f506e84bbb112478)), closes [#122](https://github.com/LerianStudio/lib-auth/issues/122)

## [3.1.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v3.0.0...v3.1.0-beta.1) (2026-07-24)


### Features

* **middleware:** forward client IP to /v1/authorize + scope decision cache by it ([cbee470](https://github.com/LerianStudio/lib-auth/commit/cbee4709d749adee4300bcccc34630c2cd9cc208))

## [3.0.0](https://github.com/LerianStudio/lib-auth/compare/v2.9.0...v3.0.0) (2026-07-22)


### ⚠ BREAKING CHANGES

* **middleware:** module path is now github.com/LerianStudio/lib-auth/v3 and the
Authorize middleware requires Fiber v3.

X-Lerian-Ref: 0x1

### Features

* **middleware:** add authz cache, circuit breaker, and bounded retry ([c0469e6](https://github.com/LerianStudio/lib-auth/commit/c0469e6741e7a20e5400b82d2912f7ea2630f016)), closes [#107](https://github.com/LerianStudio/lib-auth/issues/107) [#127](https://github.com/LerianStudio/lib-auth/issues/127) [#127](https://github.com/LerianStudio/lib-auth/issues/127) [#108](https://github.com/LerianStudio/lib-auth/issues/108)
* **middleware:** add fail-closed AUTH_REQUIRED option ([f7fff6c](https://github.com/LerianStudio/lib-auth/commit/f7fff6c2ab78b30c4d851d2ab39afc362c8a2570)), closes [#107](https://github.com/LerianStudio/lib-auth/issues/107)
* **middleware:** add M2M authentication gate ([2034198](https://github.com/LerianStudio/lib-auth/commit/20341984c8c3ca57db0abf7c6bd57c85b981d15a))
* **middleware:** add opt-in local JWT signature verification ([#128](https://github.com/LerianStudio/lib-auth/issues/128)) ([48b81a3](https://github.com/LerianStudio/lib-auth/commit/48b81a355cabbc65fc2fe229b6b214c9fa62fc37)), closes [#106](https://github.com/LerianStudio/lib-auth/issues/106)
* **middleware:** add optional issuer pinning to M2M gate ([5afd305](https://github.com/LerianStudio/lib-auth/commit/5afd3055d9d4a8439e71c5fa78ef75afc68f7624))
* **middleware:** expose M2M identity via request context ([c48393a](https://github.com/LerianStudio/lib-auth/commit/c48393ac6cbeb0494524dccfb8e35ee6eb5e5375)), closes [#125](https://github.com/LerianStudio/lib-auth/issues/125)
* **middleware:** forward product on M2M auth (flag-gated) ([93c44db](https://github.com/LerianStudio/lib-auth/commit/93c44dbc7155db5a4d5e857139e9b35d7ba5847f))
* **middleware:** migrate to Fiber v3, cut /v3 major ([024a909](https://github.com/LerianStudio/lib-auth/commit/024a90903ac84277ade60603a38c726b89af5b00))
* real M2M subject and token type whitelist ([e31ac53](https://github.com/LerianStudio/lib-auth/commit/e31ac531043129eee3394afd88d70cd6ad1b8b7e))


### Bug Fixes

* **middleware:** return zero M2MIdentity when reporting absent ([25fc4ec](https://github.com/LerianStudio/lib-auth/commit/25fc4ec9a44aff13964117ef96420d59468530a2)), closes [#126](https://github.com/LerianStudio/lib-auth/issues/126)

## [3.0.0-beta.9](https://github.com/LerianStudio/lib-auth/compare/v3.0.0-beta.8...v3.0.0-beta.9) (2026-07-21)

## [3.0.0-beta.8](https://github.com/LerianStudio/lib-auth/compare/v3.0.0-beta.7...v3.0.0-beta.8) (2026-07-21)


### Features

* **middleware:** add opt-in local JWT signature verification ([#128](https://github.com/LerianStudio/lib-auth/issues/128)) ([48b81a3](https://github.com/LerianStudio/lib-auth/commit/48b81a355cabbc65fc2fe229b6b214c9fa62fc37)), closes [#106](https://github.com/LerianStudio/lib-auth/issues/106)

## [3.0.0-beta.7](https://github.com/LerianStudio/lib-auth/compare/v3.0.0-beta.6...v3.0.0-beta.7) (2026-07-21)


### Features

* **middleware:** add authz cache, circuit breaker, and bounded retry ([c0469e6](https://github.com/LerianStudio/lib-auth/commit/c0469e6741e7a20e5400b82d2912f7ea2630f016)), closes [#107](https://github.com/LerianStudio/lib-auth/issues/107) [#127](https://github.com/LerianStudio/lib-auth/issues/127) [#127](https://github.com/LerianStudio/lib-auth/issues/127) [#108](https://github.com/LerianStudio/lib-auth/issues/108)

## [3.0.0-beta.6](https://github.com/LerianStudio/lib-auth/compare/v3.0.0-beta.5...v3.0.0-beta.6) (2026-07-21)


### Features

* **middleware:** add fail-closed AUTH_REQUIRED option ([f7fff6c](https://github.com/LerianStudio/lib-auth/commit/f7fff6c2ab78b30c4d851d2ab39afc362c8a2570)), closes [#107](https://github.com/LerianStudio/lib-auth/issues/107)

## [3.0.0-beta.5](https://github.com/LerianStudio/lib-auth/compare/v3.0.0-beta.4...v3.0.0-beta.5) (2026-07-20)


### Features

* **middleware:** expose M2M identity via request context ([c48393a](https://github.com/LerianStudio/lib-auth/commit/c48393ac6cbeb0494524dccfb8e35ee6eb5e5375)), closes [#125](https://github.com/LerianStudio/lib-auth/issues/125)


### Bug Fixes

* **middleware:** return zero M2MIdentity when reporting absent ([25fc4ec](https://github.com/LerianStudio/lib-auth/commit/25fc4ec9a44aff13964117ef96420d59468530a2)), closes [#126](https://github.com/LerianStudio/lib-auth/issues/126)

## [3.0.0-beta.4](https://github.com/LerianStudio/lib-auth/compare/v3.0.0-beta.3...v3.0.0-beta.4) (2026-07-20)


### Features

* **middleware:** add M2M authentication gate ([2034198](https://github.com/LerianStudio/lib-auth/commit/20341984c8c3ca57db0abf7c6bd57c85b981d15a))
* **middleware:** add optional issuer pinning to M2M gate ([5afd305](https://github.com/LerianStudio/lib-auth/commit/5afd3055d9d4a8439e71c5fa78ef75afc68f7624))

## [3.0.0-beta.3](https://github.com/LerianStudio/lib-auth/compare/v3.0.0-beta.2...v3.0.0-beta.3) (2026-07-17)


### Features

* **middleware:** forward product on M2M auth (flag-gated) ([93c44db](https://github.com/LerianStudio/lib-auth/commit/93c44dbc7155db5a4d5e857139e9b35d7ba5847f))

## [3.0.0-beta.2](https://github.com/LerianStudio/lib-auth/compare/v3.0.0-beta.1...v3.0.0-beta.2) (2026-07-16)


### Features

* real M2M subject and token type whitelist ([e31ac53](https://github.com/LerianStudio/lib-auth/commit/e31ac531043129eee3394afd88d70cd6ad1b8b7e))

## [3.0.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v2.9.0...v3.0.0-beta.1) (2026-07-15)


### ⚠ BREAKING CHANGES

* **middleware:** module path is now github.com/LerianStudio/lib-auth/v3 and the
Authorize middleware requires Fiber v3.

X-Lerian-Ref: 0x1

### Features

* **middleware:** migrate to Fiber v3, cut /v3 major ([024a909](https://github.com/LerianStudio/lib-auth/commit/024a90903ac84277ade60603a38c726b89af5b00))

## [2.9.0](https://github.com/LerianStudio/lib-auth/compare/v2.8.1...v2.9.0) (2026-06-26)


### Features

* **middleware:** forward product on user-flow authorization ([e597ae2](https://github.com/LerianStudio/lib-auth/commit/e597ae23b7ba881681f24689d3a8580c2f98b6e7))


### Bug Fixes

* **middleware:** fail closed when normal-user JWT has no sub claim ([bce4655](https://github.com/LerianStudio/lib-auth/commit/bce4655cbb30c61d3bec0447b80a2506f7d04ed5))

## [2.9.0-beta.3](https://github.com/LerianStudio/lib-auth/compare/v2.9.0-beta.2...v2.9.0-beta.3) (2026-06-25)

## [2.9.0-beta.2](https://github.com/LerianStudio/lib-auth/compare/v2.9.0-beta.1...v2.9.0-beta.2) (2026-06-25)


### Bug Fixes

* **middleware:** fail closed when normal-user JWT has no sub claim ([bce4655](https://github.com/LerianStudio/lib-auth/commit/bce4655cbb30c61d3bec0447b80a2506f7d04ed5))

## [2.9.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v2.8.2-beta.1...v2.9.0-beta.1) (2026-06-23)


### Features

* **middleware:** forward product on user-flow authorization ([e597ae2](https://github.com/LerianStudio/lib-auth/commit/e597ae23b7ba881681f24689d3a8580c2f98b6e7))

## [2.8.2-beta.1](https://github.com/LerianStudio/lib-auth/compare/v2.8.1...v2.8.2-beta.1) (2026-06-17)

## [2.8.1](https://github.com/LerianStudio/lib-auth/compare/v2.8.0...v2.8.1) (2026-06-16)

## [2.8.0](https://github.com/LerianStudio/lib-auth/compare/v2.7.0...v2.8.0) (2026-05-18)


### Bug Fixes

* **security:** redact clientSecret from tracing span payload ([fb15a94](https://github.com/LerianStudio/lib-auth/commit/fb15a9486a5d937ff45a7f9a2c7cc18fd6018569))

## [2.8.0-beta.5](https://github.com/LerianStudio/lib-auth/compare/v2.8.0-beta.4...v2.8.0-beta.5) (2026-05-18)

## [2.8.0-beta.4](https://github.com/LerianStudio/lib-auth/compare/v2.8.0-beta.3...v2.8.0-beta.4) (2026-05-18)


### Bug Fixes

* **security:** redact clientSecret from tracing span payload ([fb15a94](https://github.com/LerianStudio/lib-auth/commit/fb15a9486a5d937ff45a7f9a2c7cc18fd6018569))

## [2.8.0-beta.3](https://github.com/LerianStudio/lib-auth/compare/v2.8.0-beta.2...v2.8.0-beta.3) (2026-05-18)

## [2.8.0-beta.2](https://github.com/LerianStudio/lib-auth/compare/v2.8.0-beta.1...v2.8.0-beta.2) (2026-05-18)

## [2.8.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v2.7.0...v2.8.0-beta.1) (2026-05-18)

## [2.7.0](https://github.com/LerianStudio/lib-auth/compare/v2.6.0...v2.7.0) (2026-04-27)


### Bug Fixes

* **deps:** bump otel/sdk and exporters to v1.43.0 (GHSA-hfvc-g4fc-pqhx) ([daaa533](https://github.com/LerianStudio/lib-auth/commit/daaa533f15cde62d2a5c6a1cabf9f3be92b21a16))

## [2.7.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v2.6.1-beta.2...v2.7.0-beta.1) (2026-04-27)


### Bug Fixes

* **deps:** bump otel/sdk and exporters to v1.43.0 (GHSA-hfvc-g4fc-pqhx) ([daaa533](https://github.com/LerianStudio/lib-auth/commit/daaa533f15cde62d2a5c6a1cabf9f3be92b21a16))

## [2.6.1-beta.2](https://github.com/LerianStudio/lib-auth/compare/v2.6.1-beta.1...v2.6.1-beta.2) (2026-04-27)

## [2.6.1-beta.1](https://github.com/LerianStudio/lib-auth/compare/v2.6.0...v2.6.1-beta.1) (2026-04-27)

## [2.6.0](https://github.com/LerianStudio/lib-auth/compare/v2.5.0...v2.6.0) (2026-03-26)


### Bug Fixes

* prevent HTTP/2 hpack panic with shared HTTP client ([0716b6f](https://github.com/LerianStudio/lib-auth/commit/0716b6ffa204f1a38613b1041c6932ae637ce8e8))

## [2.6.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v2.5.0...v2.6.0-beta.1) (2026-03-26)


### Bug Fixes

* prevent HTTP/2 hpack panic with shared HTTP client ([0716b6f](https://github.com/LerianStudio/lib-auth/commit/0716b6ffa204f1a38613b1041c6932ae637ce8e8))

## [2.5.0](https://github.com/LerianStudio/lib-auth/compare/v2.4.0...v2.5.0) (2026-03-21)


### Features

* make gRPC interceptor tenant-aware with streaming support ([f4dae96](https://github.com/LerianStudio/lib-auth/commit/f4dae96c438554ca65c8fff5336c45410cb9d67d))
* **middleware:** migrate to lib-commons v4 API ([2e12d9b](https://github.com/LerianStudio/lib-auth/commit/2e12d9b1598eaafb27b1b427d8006a24eeea18ca))


### Bug Fixes

* **auth/middleware:** handle numeric code field in auth error response ([165db5f](https://github.com/LerianStudio/lib-auth/commit/165db5fdd324bb56304edd96b7e4d4579e351ade))
* **auth/middleware:** prevent panic on logger initialization failure ([6ba51e5](https://github.com/LerianStudio/lib-auth/commit/6ba51e5df9cbbdf62fc906c1837d6de41641946a))
* replace deprecated commons API calls ([805aadb](https://github.com/LerianStudio/lib-auth/commit/805aadb8ff2f1a6a8547733eeaf2618220511ee7))
* **auth/middleware:** return 401 instead of 500 for malformed tokens ([4f51877](https://github.com/LerianStudio/lib-auth/commit/4f51877ef95b4db01304cb9df5ba3a38919e55ff))
* **tests:** use safe find -exec instead of xargs pipeline :bug: ([da45b1a](https://github.com/LerianStudio/lib-auth/commit/da45b1ad9464aaf7925d932cd5af6b50a58562ea))

## [2.5.0-beta.10](https://github.com/LerianStudio/lib-auth/compare/v2.5.0-beta.9...v2.5.0-beta.10) (2026-03-21)

## [2.5.0-beta.9](https://github.com/LerianStudio/lib-auth/compare/v2.5.0-beta.8...v2.5.0-beta.9) (2026-03-20)


### Bug Fixes

* **auth/middleware:** handle numeric code field in auth error response ([165db5f](https://github.com/LerianStudio/lib-auth/commit/165db5fdd324bb56304edd96b7e4d4579e351ade))

## [2.5.0-beta.8](https://github.com/LerianStudio/lib-auth/compare/v2.5.0-beta.7...v2.5.0-beta.8) (2026-03-17)


### Bug Fixes

* **auth/middleware:** return 401 instead of 500 for malformed tokens ([4f51877](https://github.com/LerianStudio/lib-auth/commit/4f51877ef95b4db01304cb9df5ba3a38919e55ff))

## [2.5.0-beta.7](https://github.com/LerianStudio/lib-auth/compare/v2.5.0-beta.6...v2.5.0-beta.7) (2026-03-10)


### Features

* **middleware:** migrate to lib-commons v4 API ([2e12d9b](https://github.com/LerianStudio/lib-auth/commit/2e12d9b1598eaafb27b1b427d8006a24eeea18ca))


### Bug Fixes

* **auth/middleware:** prevent panic on logger initialization failure ([6ba51e5](https://github.com/LerianStudio/lib-auth/commit/6ba51e5df9cbbdf62fc906c1837d6de41641946a))

## [2.5.0-beta.6](https://github.com/LerianStudio/lib-auth/compare/v2.5.0-beta.5...v2.5.0-beta.6) (2026-02-27)


### Features

* make gRPC interceptor tenant-aware with streaming support ([f4dae96](https://github.com/LerianStudio/lib-auth/commit/f4dae96c438554ca65c8fff5336c45410cb9d67d))


### Bug Fixes

* replace deprecated commons API calls ([805aadb](https://github.com/LerianStudio/lib-auth/commit/805aadb8ff2f1a6a8547733eeaf2618220511ee7))

## [2.5.0-beta.5](https://github.com/LerianStudio/lib-auth/compare/v2.5.0-beta.4...v2.5.0-beta.5) (2026-02-20)

## [2.5.0-beta.4](https://github.com/LerianStudio/lib-auth/compare/v2.5.0-beta.3...v2.5.0-beta.4) (2026-02-20)

## [2.5.0-beta.3](https://github.com/LerianStudio/lib-auth/compare/v2.5.0-beta.2...v2.5.0-beta.3) (2026-02-20)

## [2.5.0-beta.2](https://github.com/LerianStudio/lib-auth/compare/v2.5.0-beta.1...v2.5.0-beta.2) (2026-02-20)

## [2.5.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v2.4.1-beta.1...v2.5.0-beta.1) (2026-02-09)


### Bug Fixes

* **tests:** use safe find -exec instead of xargs pipeline :bug: ([da45b1a](https://github.com/LerianStudio/lib-auth/commit/da45b1ad9464aaf7925d932cd5af6b50a58562ea))

## [2.4.1-beta.1](https://github.com/LerianStudio/lib-auth/compare/v2.4.0...v2.4.1-beta.1) (2026-02-03)

## [2.4.0](https://github.com/LerianStudio/lib-auth/compare/v2.3.0...v2.4.0) (2026-01-27)


### Bug Fixes

* prevent logger nil in the healthcheck func ([2688975](https://github.com/LerianStudio/lib-auth/commit/26889750911b6d2a6c40f00ebdefdcc8bd0510fd))
* prevent panic from nil logger in NewAuthClient ([45b8993](https://github.com/LerianStudio/lib-auth/commit/45b899341fbed68ffc8a72a58ddb190002949b02))

## [2.4.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v2.3.0...v2.4.0-beta.1) (2025-12-24)

## [2.3.0](https://github.com/LerianStudio/lib-auth/compare/v2.2.0...v2.3.0) (2025-11-07)


### Features

* add gRPC authorization middleware ([3de624f](https://github.com/LerianStudio/lib-auth/commit/3de624f64b52b286ce40a47589708c80f6edca7e))

## [2.3.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v2.2.0...v2.3.0-beta.1) (2025-11-05)


### Features

* add gRPC authorization middleware ([3de624f](https://github.com/LerianStudio/lib-auth/commit/3de624f64b52b286ce40a47589708c80f6edca7e))

## [2.2.0](https://github.com/LerianStudio/lib-auth/compare/v2.1.0...v2.2.0) (2025-08-08)


### Bug Fixes

* **middleware:** move early return before span creation to prevent memory leak ([36f9a18](https://github.com/LerianStudio/lib-auth/commit/36f9a18f59641324e14422f7bea04e9eff10e92e))
* move span.End() before returns and update span attribute names for consistency ([1189118](https://github.com/LerianStudio/lib-auth/commit/1189118b43dc47a3e0a645494a59cc20001eacac))

## [2.2.0-beta.2](https://github.com/LerianStudio/lib-auth/compare/v2.2.0-beta.1...v2.2.0-beta.2) (2025-08-08)

## [2.2.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v2.1.0...v2.2.0-beta.1) (2025-08-08)


### Bug Fixes

* **middleware:** move early return before span creation to prevent memory leak ([36f9a18](https://github.com/LerianStudio/lib-auth/commit/36f9a18f59641324e14422f7bea04e9eff10e92e))
* move span.End() before returns and update span attribute names for consistency ([1189118](https://github.com/LerianStudio/lib-auth/commit/1189118b43dc47a3e0a645494a59cc20001eacac))

## [2.1.0](https://github.com/LerianStudio/lib-auth/compare/v2.0.0...v2.1.0) (2025-08-01)

## [2.1.0-beta.2](https://github.com/LerianStudio/lib-auth/compare/v2.1.0-beta.1...v2.1.0-beta.2) (2025-08-01)

## [2.1.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v2.0.0...v2.1.0-beta.1) (2025-08-01)

## [2.0.0](https://github.com/LerianStudio/lib-auth/compare/v1.16.0...v2.0.0) (2025-07-31)


### ⚠ BREAKING CHANGES

* import paths will need to change to v2

### Code Refactoring

* update module to v2 ([d3e9278](https://github.com/LerianStudio/lib-auth/commit/d3e927898b486cf9f7ca8a766c854135de565897))

## [2.0.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v1.16.0...v2.0.0-beta.1) (2025-07-31)


### ⚠ BREAKING CHANGES

* import paths will need to change to v2

### Code Refactoring

* update module to v2 ([d3e9278](https://github.com/LerianStudio/lib-auth/commit/d3e927898b486cf9f7ca8a766c854135de565897))

## [1.16.0](https://github.com/LerianStudio/lib-auth/compare/v1.15.0...v1.16.0) (2025-07-31)


### Features

* **middleware:** enhance tracing with request ID and auth input attributes ([5aa7a2d](https://github.com/LerianStudio/lib-auth/commit/5aa7a2d5bc8fba588743a6241af7f4a5a71bb788))


### Bug Fixes

* Adjusting the function GetApplicationToken to accept when enabled flag is false or auth address is empty. ([01e9608](https://github.com/LerianStudio/lib-auth/commit/01e96080ace8f928b8564b724436b4b46e65e6de))
* Removing log info where the logger is not initiate. ([21f1367](https://github.com/LerianStudio/lib-auth/commit/21f1367cc64841e1fbf482222f3943cb9217066c))

## [1.16.0-beta.5](https://github.com/LerianStudio/lib-auth/compare/v1.16.0-beta.4...v1.16.0-beta.5) (2025-07-30)

## [1.16.0-beta.4](https://github.com/LerianStudio/lib-auth/compare/v1.16.0-beta.3...v1.16.0-beta.4) (2025-07-30)

## [1.16.0-beta.3](https://github.com/LerianStudio/lib-auth/compare/v1.16.0-beta.2...v1.16.0-beta.3) (2025-07-29)


### Features

* **middleware:** enhance tracing with request ID and auth input attributes ([5aa7a2d](https://github.com/LerianStudio/lib-auth/commit/5aa7a2d5bc8fba588743a6241af7f4a5a71bb788))

## [1.16.0-beta.2](https://github.com/LerianStudio/lib-auth/compare/v1.16.0-beta.1...v1.16.0-beta.2) (2025-07-28)


### Bug Fixes

* Removing log info where the logger is not initiate. ([21f1367](https://github.com/LerianStudio/lib-auth/commit/21f1367cc64841e1fbf482222f3943cb9217066c))

## [1.16.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v1.15.0...v1.16.0-beta.1) (2025-07-28)


### Bug Fixes

* Adjusting the function GetApplicationToken to accept when enabled flag is false or auth address is empty. ([01e9608](https://github.com/LerianStudio/lib-auth/commit/01e96080ace8f928b8564b724436b4b46e65e6de))

## [1.15.0](https://github.com/LerianStudio/lib-auth/compare/v1.14.1...v1.15.0) (2025-07-18)


### Features

* **middleware:** add OpenTelemetry tracing to auth middleware functions ([df3d8af](https://github.com/LerianStudio/lib-auth/commit/df3d8af0b94a45881bcbb42e7d869e15cf4d72e9))

## [1.15.0-beta.3](https://github.com/LerianStudio/lib-auth/compare/v1.15.0-beta.2...v1.15.0-beta.3) (2025-07-18)

## [1.15.0-beta.2](https://github.com/LerianStudio/lib-auth/compare/v1.15.0-beta.1...v1.15.0-beta.2) (2025-07-15)


### Features

* **middleware:** add OpenTelemetry tracing to auth middleware functions ([df3d8af](https://github.com/LerianStudio/lib-auth/commit/df3d8af0b94a45881bcbb42e7d869e15cf4d72e9))

## [1.15.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v1.14.1...v1.15.0-beta.1) (2025-07-02)

## [1.14.1](https://github.com/LerianStudio/lib-auth/compare/v1.14.0...v1.14.1) (2025-05-16)

## [1.14.1-beta.1](https://github.com/LerianStudio/lib-auth/compare/v1.14.0...v1.14.1-beta.1) (2025-05-16)

## [1.14.0](https://github.com/LerianStudio/lib-auth/compare/v1.13.0...v1.14.0) (2025-04-17)


### Bug Fixes

* update error status code response ([8316c23](https://github.com/LerianStudio/lib-auth/commit/8316c230fc8c971134a4c703a1a9d7c1c8a251ce))

## [1.14.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v1.13.0...v1.14.0-beta.1) (2025-04-17)


### Bug Fixes

* update error status code response ([8316c23](https://github.com/LerianStudio/lib-auth/commit/8316c230fc8c971134a4c703a1a9d7c1c8a251ce))

## [1.13.0](https://github.com/LerianStudio/lib-auth/compare/v1.12.0...v1.13.0) (2025-04-10)


### Features

* add gitignore ([6cf7882](https://github.com/LerianStudio/lib-auth/commit/6cf78824cce67015a69472c53bf157407bb16fb5))
* improve authorization error responses and add commons logger ([5caa005](https://github.com/LerianStudio/lib-auth/commit/5caa00590281cac4af026c66aca2442410bd7ed9))


### Bug Fixes

* add getTokenHeader function again ([33d6f7f](https://github.com/LerianStudio/lib-auth/commit/33d6f7f277a1be82cbd7175f95fb5f9d61984746))
* add gitignore file ([5c8beb7](https://github.com/LerianStudio/lib-auth/commit/5c8beb71f001bc4afad0a83b5da0348255414d95))
* remove .idea folder ([484171b](https://github.com/LerianStudio/lib-auth/commit/484171b300782c023995b0ad47d6fc848260a70c))
* remove gitignore to remove .idea folder ([b10d2f2](https://github.com/LerianStudio/lib-auth/commit/b10d2f2734f103d7b71761f5723da080bf6d8abc))

## [1.13.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v1.12.0...v1.13.0-beta.1) (2025-04-10)


### Features

* add gitignore ([6cf7882](https://github.com/LerianStudio/lib-auth/commit/6cf78824cce67015a69472c53bf157407bb16fb5))
* improve authorization error responses and add commons logger ([5caa005](https://github.com/LerianStudio/lib-auth/commit/5caa00590281cac4af026c66aca2442410bd7ed9))


### Bug Fixes

* add getTokenHeader function again ([33d6f7f](https://github.com/LerianStudio/lib-auth/commit/33d6f7f277a1be82cbd7175f95fb5f9d61984746))
* add gitignore file ([5c8beb7](https://github.com/LerianStudio/lib-auth/commit/5c8beb71f001bc4afad0a83b5da0348255414d95))
* remove .idea folder ([484171b](https://github.com/LerianStudio/lib-auth/commit/484171b300782c023995b0ad47d6fc848260a70c))
* remove gitignore to remove .idea folder ([b10d2f2](https://github.com/LerianStudio/lib-auth/commit/b10d2f2734f103d7b71761f5723da080bf6d8abc))

## [1.12.0](https://github.com/LerianStudio/lib-auth/compare/v1.11.0...v1.12.0) (2025-04-07)


### Bug Fixes

* improve get token from header utility func ([3f4e3e6](https://github.com/LerianStudio/lib-auth/commit/3f4e3e68d872f8e4e16435360ef494c3e87e58e2))
* split bearer from token before parsing token ([5963fc5](https://github.com/LerianStudio/lib-auth/commit/5963fc5408b93c5d03a6419c75521e31526a0558))

## [1.12.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v1.11.0...v1.12.0-beta.1) (2025-04-07)


### Bug Fixes

* improve get token from header utility func ([3f4e3e6](https://github.com/LerianStudio/lib-auth/commit/3f4e3e68d872f8e4e16435360ef494c3e87e58e2))
* split bearer from token before parsing token ([5963fc5](https://github.com/LerianStudio/lib-auth/commit/5963fc5408b93c5d03a6419c75521e31526a0558))

## [1.11.0](https://github.com/LerianStudio/lib-auth/compare/v1.10.0...v1.11.0) (2025-04-04)


### Bug Fixes

* add missing token error in authorization middleware ([b71fba3](https://github.com/LerianStudio/lib-auth/commit/b71fba38dd514ad60acda0109e9e909a957a913e))

## [1.11.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v1.10.0...v1.11.0-beta.1) (2025-04-04)


### Bug Fixes

* add missing token error in authorization middleware ([b71fba3](https://github.com/LerianStudio/lib-auth/commit/b71fba38dd514ad60acda0109e9e909a957a913e))

## [1.10.0](https://github.com/LerianStudio/lib-auth/compare/v1.9.0...v1.10.0) (2025-04-01)


### Bug Fixes

* add plugin-auth enabled validation for the get application token func ([0c8bf8d](https://github.com/LerianStudio/lib-auth/commit/0c8bf8d8312f4829993921b47dce1e3637ec7db4))

## [1.10.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v1.9.0...v1.10.0-beta.1) (2025-04-01)


### Bug Fixes

* add plugin-auth enabled validation for the get application token func ([0c8bf8d](https://github.com/LerianStudio/lib-auth/commit/0c8bf8d8312f4829993921b47dce1e3637ec7db4))

## [1.9.0](https://github.com/LerianStudio/lib-auth/compare/v1.8.0...v1.9.0) (2025-04-01)

## [1.9.0-beta.2](https://github.com/LerianStudio/lib-auth/compare/v1.9.0-beta.1...v1.9.0-beta.2) (2025-03-24)

## [1.9.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v1.8.0...v1.9.0-beta.1) (2025-03-24)

## [1.8.0](https://github.com/LerianStudio/lib-auth/compare/v1.7.0...v1.8.0) (2025-03-21)


### Features

* add get plugin token func ([6ab9cb3](https://github.com/LerianStudio/lib-auth/commit/6ab9cb3bf0646f2b5a16abad101935ba6931feb1))


### Bug Fixes

* add enabled validation before health check ([38bd0f5](https://github.com/LerianStudio/lib-auth/commit/38bd0f5faef0ec181593c2b102ccb0500bbcb38c))

## [1.8.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v1.7.0...v1.8.0-beta.1) (2025-03-21)


### Features

* add get plugin token func ([6ab9cb3](https://github.com/LerianStudio/lib-auth/commit/6ab9cb3bf0646f2b5a16abad101935ba6931feb1))


### Bug Fixes

* add enabled validation before health check ([38bd0f5](https://github.com/LerianStudio/lib-auth/commit/38bd0f5faef0ec181593c2b102ccb0500bbcb38c))

## [1.7.0](https://github.com/LerianStudio/lib-auth/compare/v1.6.0...v1.7.0) (2025-03-18)


### Features

* add health check call when instantiating a new auth client ([16eee94](https://github.com/LerianStudio/lib-auth/commit/16eee940ef49b891759849b0d1d81bf9adf09c4f))


### Bug Fixes

* fix only one cuddle assignment allowed ([753d652](https://github.com/LerianStudio/lib-auth/commit/753d652b64dbb21c003cb322822f13333f02e1d1))
* fix only one cuddle assignment allowed ([0307fb9](https://github.com/LerianStudio/lib-auth/commit/0307fb95279e3071cabd9b874dd7dfd0f669815f))
* remove extra empty line, lint issue ([6975ed5](https://github.com/LerianStudio/lib-auth/commit/6975ed57380c1a6e20b7f296bdd9aa231961899c))

## [1.7.0-beta.1](https://github.com/LerianStudio/lib-auth/compare/v1.6.0...v1.7.0-beta.1) (2025-03-18)


### Features

* add health check call when instantiating a new auth client ([16eee94](https://github.com/LerianStudio/lib-auth/commit/16eee940ef49b891759849b0d1d81bf9adf09c4f))


### Bug Fixes

* fix only one cuddle assignment allowed ([753d652](https://github.com/LerianStudio/lib-auth/commit/753d652b64dbb21c003cb322822f13333f02e1d1))
* fix only one cuddle assignment allowed ([0307fb9](https://github.com/LerianStudio/lib-auth/commit/0307fb95279e3071cabd9b874dd7dfd0f669815f))
* remove extra empty line, lint issue ([6975ed5](https://github.com/LerianStudio/lib-auth/commit/6975ed57380c1a6e20b7f296bdd9aa231961899c))

## [1.6.0](https://github.com/LerianStudio/lib-auth/compare/v1.5.0...v1.6.0) (2025-03-12)

## [1.5.0](https://github.com/LerianStudio/auth-lib/compare/v1.4.0...v1.5.0) (2025-03-06)


### Bug Fixes

* fixing the conditional ([715941b](https://github.com/LerianStudio/auth-lib/commit/715941b347324d06ed5933cbd0108d85fd59db56))

## [1.4.0](https://github.com/LerianStudio/auth-lib/compare/v1.3.0...v1.4.0) (2025-03-05)


### Bug Fixes

* rename module ([d68a627](https://github.com/LerianStudio/auth-lib/commit/d68a627590ebda62496dd604658c66edc074ed29))

## [1.3.0](https://github.com/LerianStudio/auth-lib/compare/v1.2.0...v1.3.0) (2025-03-05)


### Bug Fixes

* removing ': ([f593906](https://github.com/LerianStudio/auth-lib/commit/f59390685bfde1d12cad3d141f82954fea4e8823))

## [1.2.0](https://github.com/LerianStudio/auth-sdk/compare/v1.1.0...v1.2.0) (2025-03-05)


### Features

* adding gihub actions to create release ([ec21956](https://github.com/LerianStudio/auth-sdk/commit/ec21956ae8679916140810b9c25f566d8359969f))

## [1.1.0](https://github.com/LerianStudio/auth-sdk/compare/v1.0.10...v1.1.0) (2025-03-05)


### Features

* organize workflow ([a1256b1](https://github.com/LerianStudio/auth-sdk/commit/a1256b19e8db9897ef894d3dc481792e38de6de0))

## [1.1.0-beta.1](https://github.com/LerianStudio/auth-sdk/compare/v1.0.10...v1.1.0-beta.1) (2025-03-05)


### Features

* organize workflow ([a1256b1](https://github.com/LerianStudio/auth-sdk/commit/a1256b19e8db9897ef894d3dc481792e38de6de0))
