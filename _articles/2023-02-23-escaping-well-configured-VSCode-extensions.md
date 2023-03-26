---
title: "Escaping well-configured VSCode extensions for profit (part 2)"
tags: ["VSCode", "path_traversal", "CVE"]
---

In this post, I’ll demonstrate how I bypassed a Webview’s `localResourceRoots` by exploiting small URL parsing differences between the browser and other VSCode logic and an over-reliance on the browser to do path normalization. This bypass allows an attacker with JavaScript execution inside a Webview to read files anywhere in the system, including those outside the `localResourceRoots`. Microsoft assigned this bug [CVE-2022-41042](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-41042) and awarded us a bounty of $7,500 (about $2,500 per minute of bug finding).

Read the full post at [https://blog.trailofbits.com/2023/02/23/escaping-well-configured-vscode-extensions-for-profit/](https://blog.trailofbits.com/2023/02/23/escaping-well-configured-vscode-extensions-for-profit/).