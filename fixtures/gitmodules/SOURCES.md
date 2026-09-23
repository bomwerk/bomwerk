# `.gitmodules` fixtures: sources & attribution

These are the **real, unmodified `.gitmodules`** files of well-known public C/C++
projects, vendored so the submodules parser is tested against inputs it did
not author (a fixture the author writes only encodes the author's assumptions).
Each is pinned to a specific commit so it never drifts. Only the small
`.gitmodules` metadata file is copied here: none of the projects' source. See
[`hostile/`](hostile/) for hand-written adversarial inputs.

Retrieved 2026-07-09 from `raw.githubusercontent.com/<repo>/<commit>/.gitmodules`.

| Fixture | Source repo | Pinned commit | Upstream license | Exercises |
|---|---|---|---|---|
| `pico-sdk.gitmodules` | [raspberrypi/pico-sdk](https://github.com/raspberrypi/pico-sdk) | `98a542c1a62fb549ffb5d66a3e5892b06276b670` | BSD-3-Clause | 5 submodules, clean `https://….git` URLs |
| `mbedtls.gitmodules` | [Mbed-TLS/mbedtls](https://github.com/Mbed-TLS/mbedtls) | `9e9eb069d6aa3db84bef07b6d83a78bdee9b1da6` | Apache-2.0 OR GPL-2.0-or-later | URL with **no** `.git` suffix |
| `openssl.gitmodules` | [openssl/openssl](https://github.com/openssl/openssl) | `234845aaabbcfef5f58a00835f0383ceabe469b5` | Apache-2.0 | 11 submodules; `.git` and bare URLs mixed; `update = rebase`; `branch = main` |
| `esp-idf.gitmodules` | [espressif/esp-idf](https://github.com/espressif/esp-idf) | `f0887bcf8763266effe3fa0b358340df226a04b5` | Apache-2.0 | 24 submodules; **relative URLs**; custom `sbom-*` keys; `shallow = true` |
| `stm32cubef4.gitmodules` | [STMicroelectronics/STM32CubeF4](https://github.com/STMicroelectronics/STM32CubeF4) | `89e6d4466578bc9eab83de8fcd1e397ceb5e5cc9` | mixed (per-component; see upstream) | 56 submodules, every one with a `branch` key, deep nested paths |

To refresh a fixture, re-fetch the same path at a **new** pinned commit and
update the commit column here in the same change.
