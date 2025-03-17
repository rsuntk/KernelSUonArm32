# KernelSU

<img src="https://kernelsu.org/logo.png" style="width: 96px;" alt="logo">

A Kernel-based root solution for Android devices.

> [!NOTE]
> Official KernelSU will never support armeabi-v7a!
>
> This is unofficial forks, all rights reserved to [@tiann](https://github.com/tiann)

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-orange.svg?logo=gnu)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![GitHub License](https://img.shields.io/github/license/tiann/KernelSU?logo=gnu)](/LICENSE)

## How to add
```
curl -LSs "https://raw.githubusercontent.com/rsuntk/KernelSUonArm32/main/kernel/setup.sh" | bash -s main
```

## What's working?

- Root access
- Manager app
- Module installations

## What's broken?

- SEPolicy patcher and some rules, causing allowlist error -13 (addressing that issue)
- Root Profile (we use magiskpolicy instead of prebuilt one)
- You tell me.

## Features

1. Kernel-based `su` and root access management.
2. Module system based on [5ec1cff's Magic Mount API on KernelSU](https://github.com/5ec1cff/KernelSU)
3. [App Profile](https://kernelsu.org/guide/app-profile.html): Lock up the root power in a cage.
4. Added experimental armeabi-v7a support

## Compatibility State

KernelSU (before v1.0.0) officially supports Android GKI 2.0 devices (kernel 5.10+). Older kernels (4.14+) are also compatible, but the kernel will have to be built manually.

With this, WSA, ChromeOS, and container-based Android are all supported.

## Usage

- [Installation Instruction](https://kernelsu.org/guide/installation.html)
- [How to build?](https://kernelsu.org/guide/how-to-build.html)
- [Official Website](https://kernelsu.org/)

## Security

For information on reporting security vulnerabilities in KernelSU, see [SECURITY.md](/SECURITY.md).

## License

- Files under the `kernel` directory are [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html).
- All other parts except the `kernel` directory are [GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html).

## Credits

- [KernelSU](https://github.com/tiann/KernelSU): Original KernelSU projects.
- [kernel-assisted-superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/): the KernelSU idea.
- [Magisk](https://github.com/topjohnwu/Magisk): the powerful root tool.
- [genuine](https://github.com/brevent/genuine/): apk v2 signature validation.
- [Diamorphine](https://github.com/m0nad/Diamorphine): some rootkit skills.
- [5ec1cff](https://github.com/5ec1cff): magic mount api implementation.
