---
title: "Secure your Apollo GraphQL server with Semgrep"
tags: ["Semgrep", "GraphQL"]
published: false
---

**tl;dr**: Our publicly available Semgrep ruleset has nine new rules to detect misconfigurations of versions 3 and 4 of the Apollo GraphQL server. Try them out with `semgrep --config p/trailofbits`!

When auditing several of our clients’ Apollo GraphQL servers, I kept finding the same issues over and over: cross-site request forgery (CSRF) that allowed attackers to perform actions on behalf of users, rate-limiting that allowed attackers to brute-force passwords or MFA tokens, and cross-origin resource sharing (CORS) misconfigurations that allowed attackers to fetch secrets that they shouldn’t have access to. Developers overlook these issues for multiple reasons: bad defaults in version 3 of the Apollo GraphQL server (e.g., the `csrfProtection` option does not default to `true`), a lack of understanding or knowledge of certain GraphQL features (e.g., [batched queries](https://www.apollographql.com/blog/apollo-client/performance/batching-client-graphql-queries/)), and a lack of understanding of certain web concepts (e.g., how the same-origin policy and CORS work).

Finding the same issues repeatedly motivated me to use some internal research and development (IRAD) time to consistently detect some of these issues in our future audits, leaving more time to find deeper, more complex bugs. Semgrep—a static analysis tool used to detect simple patterns that occur in a single file—was the obvious tool for the job because the issues are easy to detect with grep-like constructs and don’t require interprocedural or other types of more complex analysis.

We open sourced Semgrep rules that find Apollo GraphQL server v3 and v4 misconfigurations. Our rules leverage Semgrep’s `taint` mode to make them easier to write and to increase their accuracy. Go test your GraphQL servers!

We previously publicly released Semgrep rules to find [Go concurrency bugs](https://blog.trailofbits.com/2021/11/08/discovering-goroutine-leaks-with-semgrep/) and [misuses of machine learning libraries](https://blog.trailofbits.com/2022/10/03/semgrep-maching-learning-static-analysis/).

# Common GraphQL issues
GraphQL has several design choices that make some vulnerabilities, such as CSRF, more prevalent than in typical REST servers. Of course, GraphQL servers also suffer from all the usual problems: access control issues (e.g., [an access control flaw in GitLab](https://hackerone.com/reports/614355) that disclosed information about private users, or [a bug in HackerOne](https://hackerone.com/reports/489146) that allowed attackers to disclose users’ confidential data), SQL injections (e.g., [a SQL injection in HackerOne’s GraphQL server](https://hackerone.com/reports/435066)), server-side request forgery (SSRF), command injection, and many others.

This blog post will cover the rules we created to detect CSRF and CORS misconfigurations. We’ll also show how using Semgrep’s taint mode can save you time and increase your rules’ accuracy by reducing the number of patterns you need to define all the ways in which a value can flow into a sink.

## CSRF
CSRF is an attack that allows malicious actors to trick users into performing unwanted operations (e.g., editing the user’s profile) in websites they’re authenticated to. If you’re unfamiliar with the details, read more about CSRF attacks in [PortSwigger’s Web Security Academy CSRF](https://portswigger.net/web-security/csrf) explanation.

### CSRF attacks in the Apollo Server
CSRF haunted the Apollo GraphQL server until the introduction of the `csrfPrevention` option. CSRF vulnerabilities are prevalent in the Apollo server because of two factors: developers mislabel mutations as queries, and the Apollo server allows users to issue [query operations with GET requests](https://www.apollographql.com/docs/apollo-server/v2/requests/#get-requests) (but not mutation operations). Queries should not change state (like a GET request in a RESTful API), while mutations are expected to change state (like POST, PATCH, PUT, or DELETE). If developers followed this convention, everything would be fine. However, I’ve yet to find a codebase that does not mislabel a mutation as a query, making these mislabeled operations immediately vulnerable to CSRF attacks.

Thankfully, the Apollo team was very aware of this and, in version 3, added the [`csrfPrevention`](https://www.apollographql.com/docs/apollo-server/security/cors/#preventing-cross-site-request-forgery-csrf) option to remove the issue altogether. It prevents CSRF attacks by ensuring that any request must have a `Content-Type` header different from `text/plain`, `application/x-www-form-urlencoded`, or `multipart/form-data`; a non-empty `X-Apollo-Operation-Name` header; or a non-empty `Apollo-Require-Preflight` header. This ensures the request will always be [preflighted](https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request), which prevents the CSRF attack.

The `csrfPrevention` option defaults to `false` in v3 and to `true` in v4, so those still using v3 need to consciously add this option in their server initialization, which, in our experience, almost never happens.

### Finding CSRF misconfigurations with Semgrep
We created two Semgrep rules to find misconfigurations in versions 3 and 4. For v3, we find all `ApolloServer` initializations where the `csrfPrevention` option is not set to true.

```yaml
patterns:
  - pattern: new ApolloServer({...})
  - pattern-not: |
      new ApolloServer({..., csrfPrevention: true, ...})
```
_Figure 1.1: [Semgrep rule that detects a misconfigured `csrfProtection` option in version 3 of the Apollo server](https://semgrep.dev/playground/r/trailofbits.javascript.apollo-graphql.v3-csrf-prevention.v3-csrf-prevention)_

For v4, we find all server initializations with the `csrfPrevention` option set to `false`.

```yaml
patterns:
  - pattern: |
      new ApolloServer({..., csrfPrevention: false, ...})
```
_Figure 1.2: [Semgrep rule that detects a misconfigured csrfProtection option in version 4 of the Apollo server](https://semgrep.dev/playground/r/trailofbits.javascript.apollo-graphql.v4-csrf-prevention.v4-csrf-prevention)_

## CORS
CORS allows a server to relax the browser’s SOP. As expected, developers sometimes relax the SOP a bit too far, which can allow attackers to fetch secrets that they should not have access to. If you are unfamiliar with the details, read more about CORS in [PortSwigger’s Web Security Academy CORS](https://portswigger.net/web-security/cors) explanation.

### Setting a CORS policy in an Apollo Server
In version 3 of the Apollo Server, a developer can set their server’s CORS policy in two ways. First, they can pass the cors argument to their `ApolloServer` class instance.

```ts
import { ApolloServer } from 'apollo-server';

const apolloServerInstance = new ApolloServer({
    cors: CORS_ORIGIN
});
```
_Figure 1.3: Configuring CORS in version 3 of an Apollo GraphQL server_

Alternatively, they can set the CORS policy on the back-end framework they are using. For example, with an [Express.js](https://expressjs.com/) back-end server, the CORS attribute is passed as an argument to the `applyMiddleware` function.

```ts
import { ApolloServer } from 'apollo-server-express';

const apolloServerInstance = new ApolloServer({});

apolloServerInstance.applyMiddleware({
    app,
    cors: CORS_ORIGIN,
});
```
_Figure 1.4: Configuring CORS in version 3 of an Apollo GraphQL server with a back-end Express server_

On version 4 of the Apollo server, the developer must set CORS on the back end itself. Therefore, writing rules for v4 is out of scope for our Apollo-specific Semgrep queries—other Semgrep rules already cover most of those cases.

Our rules for version 3 cover uses of Express.js and the [batteries-included](http://apollographql.com/docs/apollo-server/v3/integrations/middleware/#apollo-server) Apollo server back ends, as these were the ones we saw in use the most. If you use a different back-end framework for your Apollo Server, our rules likely won’t work, but we accept PRs at [trailofbits/semgrep-rules](https://github.com/trailofbits/semgrep-rules)! It should be effortless to adapt them based on the existing queries. ;)

### Finding missing CORS policies
The rules for each back end are very similar, so let’s look at one of them—the one that detects CORS misconfigurations in the batteries-included Apollo server. We have two rules in the same file: one to detect cases where a CORS policy is not defined and one to detect a poorly configured CORS policy.

To detect missing CORS policies, we look for `ApolloServer` instantiations where the cors argument is undefined. We also need to ensure that the `ApolloServer` comes from the `apollo-server` package (the `ApolloServer` class could also come from the `apollo-server-express` package, but we don’t want to catch these cases). The query is shown in figure 1.5.

```yaml
patterns:
  - pattern-either:
      - pattern-inside: |
          $X = require('apollo-server');
          ...
      - pattern-inside: |
          import 'apollo-server';
          ...
  - pattern: |
      new ApolloServer({...})
  - pattern-not: |
      new ApolloServer({..., cors: ..., ...})
```
_Figure 1.5: Semgrep rule that detects a missing CORS policy in an Apollo GraphQL server (v3)_

### Finding bad CORS policies
To detect bad CORS policies, it’s not as simple. We have to detect several cases:
 - Cases where the origin is set to `true`—A `true` origin tells the server to accept all origins.
 - Cases where the origin is set to `null`—An attacker can trick a user into making requests from a `null` origin from, for example, a sandboxed iframe.
 - Cases where the origin is a regex with an unescaped dot character—In regex, a dot matches *any* character, so if we are using the `/api.example.com$/` regex, it will match the `apiXexample.com` domain, which could potentially be controlled by an attacker.
 - Cases where the origin does not finish with the `$` character—In regex, the `$` character matches the end of the string, so if we are using the `/api.example.com/` regex, it will also match the `api.example.com.attacker.com` domain, an attacker-controlled domain.

And these will not cover *every* possible bad CORS policy (e.g., a bad CORS policy could simply include an attacker domain or a domain that allows an attacker to upload HTML code). We test all the cases described above with the rule in the figure below.

```yaml
pattern-either:
  # 'true' mean that every origin is reflected
  - pattern: |
      true
  # the '.' character is not escaped
  - pattern-regex: ^/.*[^\\]\..*/$
  # the regex does not end with '$'
  - pattern-regex: ^/.*[^$]/$
  # An attacker can make requests from ‘null’ origins
  - pattern: |
      'null'
```
_Figure 1.6: Semgrep pattern that detects bad CORS origins_

These bad origins can be used by themselves or inside an array. To test for both cases, we first check occurrences of the `$CORS_SINGLE_ORIGIN` metavariable that are isolated or in an array and then use a `metavariable-pattern` to define what is a bad origin with the pattern we’ve created in figure 1.6.

```yaml
pattern-either:
  - patterns:
      # pattern alone or inside an array
      - pattern-either:
          - pattern: |
              $CORS_SINGLE_ORIGIN
          - pattern: |
              [..., $CORS_SINGLE_ORIGIN, ...]
      - metavariable-pattern:
          metavariable: $CORS_SINGLE_ORIGIN
          pattern-either:
             # <The bad origin checks from the previous figure>
```
_Figure 1.7: Semgrep pattern that detects bad CORS origins in a single entry or in an array_

Finally, we need to find uses of this origin inside an `ApolloServer` initialization. We do so with the following pattern: `new ApolloServer({..., cors: $CORS_ORIGIN, ...})`

This `$CORS_ORIGIN` can be used inline (e.g., `cors: true`), or it can come from a variable (e.g., `cors: corsOriginVariableDefineElsewhere`). It is laborious to define all the possible places that the origin could have come from. Thankfully, we don’t need to do so with [Semgrep’s taint mode](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/)!

We need to define only the following:
 - [pattern-sources](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/#sources): the bad CORS policy—We define it as `{origin: $BAD_CORS_ORIGIN}` where the `$BAD_CORS_ORIGIN` metavariable is the pattern we defined above for a bad origin.
 - [pattern-sinks](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/#sinks): where the bad CORS policy should *not* flow to—We define it as the `$CORS_ORIGIN` metavariable in the pattern new `ApolloServer({..., cors: $CORS_ORIGIN, ...})`.

With `taint` mode, we can catch many ways in which the CORS policy can be set: directly (Case 1 in figure 1.8), through a variable that configures the entire CORS policy (Case 2), through a variable that sets only the origin (Case 3), and many other setups that we do not want to define by hand.

```ts
// Case 1: Has a very permissive 'cors' (true)
const apollo_server_bad_1 = new ApolloServer({
    //ruleid: apollo-graphql-v3-bad-cors
    cors: { origin: true }
});

// Case 2: Has a very permissive 'cors' from a variable
const bad_CORS_policy = { origin: true }
const apollo_server_bad_2 = new ApolloServer({
    //ruleid: apollo-graphql-v3-bad-cors
    cors: bad_CORS_policy
});

// Case 3: Has a very permissive 'cors' from a variable (just the origin)
const bad_origin = true;
const apollo_server_bad_3 = new ApolloServer({
    //ruleid: apollo-graphql-v3-bad-cors
    cors: { origin: bad_origin }
});
```
_Figure 1.8: Several test cases that Semgrep’s taint mode helps catch for free_

The entire commented rule is shown in figure 1.9.

```yaml
mode: taint
pattern-sources:
  - patterns:
      - pattern-inside: |
          { origin: $BAD_CORS_ORIGIN }
      - metavariable-pattern:
          metavariable: $BAD_CORS_ORIGIN
          pattern-either:
            # 'true' means that every origin is reflected
            - pattern: |
                true
            - patterns:
                # pattern alone or inside an array
                - pattern-either:
                    - pattern: |
                        $CORS_SINGLE_ORIGIN
                    - pattern: |
                        [..., $CORS_SINGLE_ORIGIN, ...]
                - metavariable-pattern:
                    metavariable: $CORS_SINGLE_ORIGIN
                    pattern-either:
                      # the '.' character is not escaped
                      - pattern-regex: ^/.*[^\\]\..*/$
                      # the regex does not end with '$'
                      - pattern-regex: ^/.*[^$]/$
                      # An attacker can make requests from ‘null’ origins
                      - pattern: |
                          'null'
pattern-sinks:
  - patterns:
      # The ApolloServer comes from the 'apollo-server' package
      - pattern-either:
          - pattern-inside: |
              $X = require('apollo-server');
              ...
          - pattern-inside: |
              import 'apollo-server';
              ...
      # The sink is the ApolloServer's cors argument
      - pattern: |
          new ApolloServer({..., cors: $CORS_ORIGIN, ...})
      # This tells Semgrep that the sink is only the $CORS_ORIGIN variable
      - focus-metavariable: $CORS_ORIGIN
```
_Figure 1.9: [Semgrep rule that detects a bad CORS policy in an Apollo GraphQL server (v3)](https://semgrep.dev/playground/r/trailofbits.javascript.apollo-graphql.v3-cors.v3-bad-cors)_

We have also created a Semgrep rule for auditors and security engineers that want to review their Apollo server’s CORS policy in detail, even when the policy might be safe. This rule reports any CORS policy that is not false or an empty array—obviously good CORS policies. It is helpful when you want to check all the hard-coded origins by hand, but it is not something that you want to integrate in your CI pipeline since it will report false positives (an audit rule). You can find the rule at [trailofbits.javascript.apollo-graphql.v3-cors-audit.v3-potentially-bad-cors](https://semgrep.dev/playground/r/trailofbits.javascript.apollo-graphql.v3-cors-audit.v3-potentially-bad-cors).

# Finishing thoughts
Semgrep excels in finding simple patterns that happen in a single file like the ones we’ve described in this post. For more complex analysis, you may want to use a tool such as [CodeQL](https://codeql.github.com/), which has its disadvantages as well: it involves a more difficult learning curve, it uses different APIs for different languages, it requires compiling the code, and it does not support some languages that Semgrep does (e.g., Rust).

One of Semgrep’s biggest limitations is that it lacks interfile and interprocedural analysis. For example, the rules above won’t catch cases where the CORS policy is set in one file and the Apollo Server initialization occurs in another file. This may now be possible with [Semgrep Pro Engine](https://semgrep.dev/products/pro-engine) (previously called DeepSemgrep), which enhances the Semgrep engine with interfile analysis capabilities. However, this feature is currently limited to paid customers and to a limited number of languages.

At Trail of Bits, we extensively use static analysis tools and usually end up writing custom rules and queries specific to our clients’ codebases. These can provide great value because they can find patterns specific to your codebase and even enforce your organization’s engineering best practices. When the rules we write are useful to the community, we like to open source them. Check them out at [trailofbits/semgrep-rules](https://github.com/trailofbits/semgrep-rules).

Use our new Apollo GraphQL rules with `semgrep --config p/trailofbits`, and try writing your own custom rules!