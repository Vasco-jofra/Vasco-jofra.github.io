---
title: "Streamline your static analysis triage with SARIF Explorer"
tags: ["VSCode", "VSCode_extension", "SARIF"]
---

I created a SARIF Explorer, a VSCode extension that allows you to triage static analysis results more effectively and with more enjoyment. You can install it through the [VSCode marketplace](https://marketplace.visualstudio.com/items?itemName=trailofbits.sarif-explorer) and find its code in our [vscode-sarif-explorer](https://github.com/trailofbits/vscode-sarif-explorer/) repo.

![](/assets/img/2024-03-24-streamlining-your-static-analysis-triage-with-SARIF-Explorer/main_cropped.png)

Here are its main features:
 - **Open multiple SARIF files**: Triage all your results at once.
 - **Browse results**: Browse results by clicking on them to open their associated location in VSCode. You can also browse a result’s dataflow steps, if present.
 - **Classify results**: Add metadata to each result by classifying it as a “bug,” “false positive,” or “TODO” and adding a custom text comment. Keyboard shortcuts are supported.
 - **Filter results**: Filter results by keyword, path (to include or exclude), level (“error,” “warning,” “note,” or “none”), and status (“bug,” “false positive,” or “TODO”).
 - **Open GitHub issues**: Copy GitHub permalinks to locations associated with results and create GitHub issues directly from SARIF Explorer.
 - **Send bugs to weAudit**: Send all bugs to weAudit once you’ve finished triaging them and continue with the weAudit workflow.
 - **Collaborate**: Share the .sarifexplorer file with your colleagues (e.g., on GitHub) to share your comments and classified results..


Read the full post at [https://blog.trailofbits.com/2024/03/20/streamline-the-static-analysis-triage-process-with-sarif-explorer/](https://blog.trailofbits.com/2024/03/20/streamline-the-static-analysis-triage-process-with-sarif-explorer/).