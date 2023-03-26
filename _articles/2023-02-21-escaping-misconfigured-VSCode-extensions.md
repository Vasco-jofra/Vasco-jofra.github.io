---
title: "Escaping misconfigured VSCode extensions (part 1)"
tags: ["VSCode", "XSS", "path_traversal"]
---

In this two-part blog, I'll cover how I found and disclosed three vulnerabilities in VSCode extensions and one vulnerability in VSCode itself (a security mitigation bypass assigned [CVE-2022-41042](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-41042) and awarded a $7,500 bounty). 

In this first part, we'll dive into the inner works of VSCode Webviews and analyze three vulnerabilities in VSCode extensions, two of which led to arbitrary local file exfiltration. We'll also look at some interesting exploitation tricks: leaking files using DNS to bypass restrictive Content-Security-Policy (CSP) policies, using srcdoc iframes to execute JavaScript, and using DNS rebinding to elevate the impact of our exploits

Read the full post at [https://blog.trailofbits.com/2023/02/21/vscode-extension-escape-vulnerability/](https://blog.trailofbits.com/2023/02/21/vscode-extension-escape-vulnerability/).