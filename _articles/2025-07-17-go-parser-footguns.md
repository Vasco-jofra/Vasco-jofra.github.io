---
title: "Unexpected security footguns in Go's parsers"
tags: ["Go", "JSON", "XML", "YAML"]
---

This blogpost contextualizes unexpected Go parser behaviors through three attack scenarios that every security engineer and Go developer should understand:

 - **(Un)Marshaling unexpected data**: How Go parsers can expose data that developers intended to be private
 - **Parser differentials**: How discrepancies between parsers enable attackers to bypass security controls when multiple services parse the same input
 - **Data format confusion**: How parsers process cross-format payloads with surprising and exploitable results

We’ll demonstrate each attack scenario with real-world examples and conclude with concrete recommendations for configuring these parsers more securely, including strategies to compensate for security gaps in Go’s standard library.

Below is a summary of the surprising behaviors we'll examine, with indicators showing their security status:

- 🟢 **Green**: Secure by default
- 🟠 **Orange**: Insecure by default but configurable
- 🔴 **Red**: Insecure by default with no secure configuration options

<!-- This colors the table below. `tr` corresponds to the rows and `td` to the columns -->
<style>
    .summaryTable tr:nth-child(1) td:nth-child(2) { background: rgba(255, 0, 0, 0.8); }
    .summaryTable tr:nth-child(1) td:nth-child(3) { background: rgba(255, 0, 0, 0.8); }
    .summaryTable tr:nth-child(1) td:nth-child(4) { background: rgba(255, 0, 0, 0.8); }
    .summaryTable tr:nth-child(1) td:nth-child(5) { background: rgba(255, 0, 0, 0.8); }
    .summaryTable tr:nth-child(3) td:nth-child(2) { background: rgba(255, 0, 0, 0.8); }
    .summaryTable tr:nth-child(3) td:nth-child(4) { background: rgba(255, 0, 0, 0.8); }
    .summaryTable tr:nth-child(4) td:nth-child(2) { background: rgba(255, 0, 0, 0.8); }
    .summaryTable tr:nth-child(5) td:nth-child(4) { background: rgba(255, 0, 0, 0.8); }
    .summaryTable tr:nth-child(6) td:nth-child(4) { background: rgba(255, 0, 0, 0.8); }
    .summaryTable tr:nth-child(7) td:nth-child(2) { background: rgba(255, 0, 0, 0.8); }
    .summaryTable tr:nth-child(7) td:nth-child(4) { background: rgba(255, 0, 0, 0.8); }

    .summaryTable tr:nth-child(2) td:nth-child(2) { background: rgba(0, 127, 0, 0.8); }
    .summaryTable tr:nth-child(2) td:nth-child(3) { background: rgba(0, 127, 0, 0.8); }
    .summaryTable tr:nth-child(2) td:nth-child(4) { background: rgba(0, 127, 0, 0.8); }
    .summaryTable tr:nth-child(2) td:nth-child(5) { background: rgba(0, 127, 0, 0.8); }
    .summaryTable tr:nth-child(3) td:nth-child(3) { background: rgba(0, 127, 0, 0.8); }
    .summaryTable tr:nth-child(3) td:nth-child(5) { background: rgba(0, 127, 0, 0.8); }
    .summaryTable tr:nth-child(4) td:nth-child(3) { background: rgba(0, 127, 0, 0.8); }
    .summaryTable tr:nth-child(4) td:nth-child(4) { background: rgba(0, 127, 0, 0.8); }
    .summaryTable tr:nth-child(4) td:nth-child(5) { background: rgba(0, 127, 0, 0.8); }
    .summaryTable tr:nth-child(6) td:nth-child(2) { background: rgba(0, 127, 0, 0.8); }
    .summaryTable tr:nth-child(6) td:nth-child(3) { background: rgba(0, 127, 0, 0.8); }
    .summaryTable tr:nth-child(6) td:nth-child(5) { background: rgba(0, 127, 0, 0.8); }
    .summaryTable tr:nth-child(7) td:nth-child(3) { background: rgba(0, 127, 0, 0.8); }
    .summaryTable tr:nth-child(7) td:nth-child(5) { background: rgba(0, 127, 0, 0.8); }

    .summaryTable tr:nth-child(5) td:nth-child(2) { background: rgba(255, 165, 0, 0.8); }
    .summaryTable tr:nth-child(5) td:nth-child(3) { background: rgba(255, 165, 0, 0.8); }
    .summaryTable tr:nth-child(5) td:nth-child(5) { background: rgba(255, 165, 0, 0.8); }
</style>

<div class="summaryTable">

|                       | JSON               | JSON v2          | XML              | YAML             |
| --------------------- | ------------------ | ---------------- | ---------------- | ---------------- |
| json:"-,..."          | YES (bad design)   | YES (bad design) | YES (bad design) | YES (bad design) |
| json:"omitempty"      | YES (expected)     | YES (expected)   | YES (expected)   | YES (expected)   |
| Duplicate keys        | YES (last)         | NO               | YES (last)       | NO               |
| Case insensitivity    | YES                | NO               | NO               | NO               |
| Unknown keys          | YES (mitigable)    | YES (mitigable)  | YES              | YES (mitigable)  |
| Garbage leading data  | NO                 | NO               | YES              | NO               |
| Garbage trailing data | YES (with Decoder) | NO               | YES              | NO               |

</div>

Read the full post at [https://blog.trailofbits.com/2025/06/17/unexpected-security-footguns-in-gos-parsers/](https://blog.trailofbits.com/2025/06/17/unexpected-security-footguns-in-gos-parsers/).