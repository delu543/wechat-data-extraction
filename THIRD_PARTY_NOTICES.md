# Third-party dependency notices

The source and Plugin archives produced by this repository do **not** contain a Python virtual
environment, third-party wheels, or an FFmpeg executable. The public bootstrap calls
`scripts/setup_runtime_tools.sh`, which installs the media packages below into a versioned private
environment on the user's own Mac using the SHA-256 allowlist in
`scripts/requirements-runtime.txt`. `pilk` is a source distribution on macOS, so its build also uses
the hash-pinned `wheel` package from `scripts/requirements-build.txt`.
The older `scripts/setup_content_tools.sh` remains a source-developer helper.
`scripts/setup_key_init_tools.sh`, which belongs only to the explicit source-development setup
workflow, separately installs the pinned Frida and compatibility packages shown here. That
installer accepts only the macOS wheels whose PyPI SHA-256 digests are recorded in
`scripts/requirements-key-init.txt`; it does not allow source-distribution fallback:

| Dependency | Pinned version | Upstream | License note |
| --- | ---: | --- | --- |
| `pilk` | 0.2.4 | <https://github.com/foyoux/pilk> | GPL-3.0 |
| `pycryptodome` | 3.23.0 | <https://www.pycryptodome.org/> | Public-domain and BSD-licensed components; see upstream distribution |
| `zstandard` | 0.23.0 | <https://github.com/indygreg/python-zstandard> | BSD-3-Clause |
| `imageio-ffmpeg` | 0.6.0 | <https://github.com/imageio/imageio-ffmpeg> | Python wrapper is BSD-2-Clause; platform wheels include a separate FFmpeg executable |
| `frida` | 17.16.4 | <https://frida.re/> | wxWindows Library Licence, Version 3.1; source-development key initialization only |
| `typing_extensions` | 4.16.0 | <https://github.com/python/typing_extensions> | PSF-2.0 |
| `wheel` | 0.45.1 | <https://github.com/pypa/wheel> | MIT; build helper only |

The locally inspected macOS `imageio-ffmpeg` wheel contains an FFmpeg 7.1 build configured with
GPL components. Its obligations are not covered by the wrapper's BSD license. Therefore neither
that wheel nor its FFmpeg executable is included in the distributable archives created here.

If a future release bundles any wheel, virtual environment, FFmpeg build, SILK decoder, or signed
Companion containing these components, the release owner must perform a new license review and
ship the applicable complete license texts, component/build BOM, notices, and corresponding-source
materials. This file is an engineering inventory, not legal advice.
