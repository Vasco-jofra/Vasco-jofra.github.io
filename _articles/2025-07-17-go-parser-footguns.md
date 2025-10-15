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

<table class="summaryTable" border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; text-align: center;">
  <tr>
    <th></th>
    <th>JSON</th>
    <th>JSON v2</th>
    <th>XML</th>
    <th>YAML</th>
  </tr>
  <tr>
    <td>json:"-,..."</td>
    <td style="background: rgba(255, 0, 0, 0.8);">YES (bad design)</td>
    <td style="background: rgba(255, 0, 0, 0.8);">YES (bad design)</td>
    <td style="background: rgba(255, 0, 0, 0.8);">YES (bad design)</td>
    <td style="background: rgba(255, 0, 0, 0.8);">YES (bad design)</td>
  </tr>
  <tr>
    <td>json:"omitempty"</td>
    <td style="background: rgba(0, 127, 0, 0.8);">YES (expected)</td>
    <td style="background: rgba(0, 127, 0, 0.8);">YES (expected)</td>
    <td style="background: rgba(0, 127, 0, 0.8);">YES (expected)</td>
    <td style="background: rgba(0, 127, 0, 0.8);">YES (expected)</td>
  </tr>
  <tr>
    <td>Duplicate keys</td>
    <td style="background: rgba(255, 0, 0, 0.8);">YES (last)</td>
    <td style="background: rgba(0, 127, 0, 0.8);">NO</td>
    <td style="background: rgba(255, 0, 0, 0.8);">YES (last)</td>
    <td style="background: rgba(0, 127, 0, 0.8);">NO</td>
  </tr>
  <tr>
    <td>Case insensitivity</td>
    <td style="background: rgba(255, 0, 0, 0.8);">YES</td>
    <td style="background: rgba(0, 127, 0, 0.8);">NO</td>
    <td style="background: rgba(0, 127, 0, 0.8);">NO</td>
    <td style="background: rgba(0, 127, 0, 0.8);">NO</td>
  </tr>
  <tr>
    <td>Unknown keys</td>
    <td style="background: rgba(255, 165, 0, 0.8);">YES (mitigable)</td>
    <td style="background: rgba(255, 165, 0, 0.8)">YES (mitigable)</td>
    <td style="background: rgba(255, 0, 0, 0.8);">YES</td>
    <td style="background: rgba(255, 165, 0, 0.8)">YES (mitigable)</td>
  </tr>
  <tr>
    <td>Garbage leading data</td>
    <td style="background: rgba(0, 127, 0, 0.8);">NO</td>
    <td style="background: rgba(0, 127, 0, 0.8);">NO</td>
    <td style="background: rgba(255, 0, 0, 0.8);">YES</td>
    <td style="background: rgba(0, 127, 0, 0.8);">NO</td>
  </tr>
  <tr>
    <td>Garbage trailing data</td>
    <td style="background: rgba(255, 0, 0, 0.8);">YES (with Decoder)</td>
    <td style="background: rgba(0, 127, 0, 0.8);">NO</td>
    <td style="background: rgba(255, 0, 0, 0.8);">YES</td>
    <td style="background: rgba(0, 127, 0, 0.8);">NO</td>
  </tr>
</table>


Read the full post at [https://blog.trailofbits.com/2025/06/17/unexpected-security-footguns-in-gos-parsers/](https://blog.trailofbits.com/2025/06/17/unexpected-security-footguns-in-gos-parsers/).