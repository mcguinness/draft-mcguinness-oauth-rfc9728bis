---
title: "Update to OAuth 2.0 Protected Resource Metadata Resource Identifier Validation"
abbrev: "Updated PRM Resource Validation"
category: std
updates: 9728

docName: "draft-mcguinness-oauth-rfc9728bis-latest"
workgroup: "Web Authorization Protocol"
area: "Security"
ipr: "trust200902"
keyword:
  - "OAuth 2.0"
  - "Protected Resource Metadata"
  - "Resource Indicator"
venue:
  group: "Web Authorization Protocol"
  type: "Working Group"
  mail: "oauth@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/oauth/"
  github: "mcguinness/draft-mcguinness-oauth-rfc9728bis"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-rfc9728bis/draft-mcguinness-oauth-rfc9728bis.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com
 -
    fullname: Aaron Parecki
    organization: Okta
    email: aaron.parecki@okta.com

normative:
  RFC3986:
  RFC6750:
  RFC8707:
  RFC9110:
  RFC9449:
  RFC9728:

informative:
  RFC6749:
  I-D.mcguinness-oauth-resource-token-resp:

...

--- abstract

RFC 9728 defines OAuth 2.0 Protected Resource Metadata, enabling
clients to dynamically discover the authorization requirements of
protected resources.  Section 3.3 of RFC 9728 requires that when
protected resource metadata is obtained via a WWW-Authenticate
challenge, the `resource` value in the metadata MUST exactly match
the URL the client used to access the protected resource.

This document updates the resource validation rule in Section 3.3
of RFC 9728 to permit the `resource` value to be any URI that
shares the same TLS origin (scheme, host, and port) as the
requested URL and whose path is a prefix of the request URL path.
All other aspects of RFC 9728 remain unchanged.

--- middle

# Introduction

This document updates one specific aspect of OAuth 2.0 Protected
Resource Metadata {{RFC9728}}: the resource validation rule defined
in Section 3.3.

Section 3.3 of {{RFC9728}} requires that when a client retrieves
protected resource metadata from a URL obtained via a
WWW-Authenticate challenge, the `resource` value in the metadata
response MUST be identical to the URL the client used to make the
request that triggered the challenge.  This exact-match rule prevents
a malicious resource from directing clients to metadata that
impersonates a different resource.

Consider a resource server at `https://api.example.com` that exposes
the following protected resources:

- `https://api.example.com/accounts`
- `https://api.example.com/transactions`
- `https://api.example.com/profile`

All three protected resources are served by the same authorization
server (`https://as.example.com`) and accept tokens with the same
audience (`https://api.example.com`).

Under the current Section 3.3 rule in {{RFC9728}}, when a client
calls `https://api.example.com/transactions` without a token, the
resource server responds:

~~~
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://api.example.com/
  .well-known/oauth-protected-resource/transactions"
~~~

The client retrieves the metadata, which per Section 3.3 of
{{RFC9728}} MUST contain a `resource` value identical to the request
URL:

~~~ json
{
  "resource": "https://api.example.com/transactions",
  "authorization_servers": ["https://as.example.com"],
  ...
}
~~~

The client then requests a token using
`https://api.example.com/transactions` as the `resource` parameter
per {{RFC8707}}.  The authorization server may issue a token whose
audience is `https://api.example.com` (covering all protected
resources on the server), but the client has no standardized way to
know this.

When the client subsequently needs to access
`https://api.example.com/accounts`, it faces one of the following
suboptimal outcomes:

1. It repeats the entire discovery and token-request flow for the
   new protected resource, wasting a round trip to the authorization
   server.

2. It speculatively reuses the existing token, which may work but
   is not grounded in any protocol signal from the resource server.

3. The authorization server must understand and enumerate every
   per-URL resource identifier that maps to a given audience,
   increasing configuration complexity.

This document relaxes the exact-match requirement for `resource`
values obtained via WWW-Authenticate discovery to a same-origin,
path-prefix match.  See {{update-section-3-3}} for the normative
specification.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

This document uses the following terms as defined in the referenced
specifications:

resource identifier:
: An HTTPS URI that identifies a protected resource or set of
  protected resources, as defined in Section 1.2 of {{RFC9728}} and
  {{RFC8707}}.

TLS origin:
: The combination of scheme, host, and port derived from a URI, as
  defined in Section 4.3.2 of {{RFC9110}} for the `https` scheme.
  Two URIs share the same TLS origin if and only if their scheme,
  host, and port (after applying default port rules) are identical.

path prefix:
: A path that matches the beginning of another path on a segment
  boundary.  See {{path-prefix-matching}} for the precise definition.

# Update to RFC 9728 Section 3.3 {#update-section-3-3}

This section contains the normative change to {{RFC9728}}.  It
updates only the resource validation rule in Section 3.3 of
{{RFC9728}} that applies when metadata is retrieved via a
WWW-Authenticate challenge.  All other requirements in Section 3.3
and the rest of {{RFC9728}} remain in effect.

## Original Rule (Replaced)

Section 3.3 of {{RFC9728}} states:

> If the protected resource metadata was retrieved from a URL
> returned by the protected resource via the WWW-Authenticate
> `resource_metadata` parameter, then the `resource` value returned
> MUST be identical to the URL that the client used to make the
> request. [...] If these values are not identical, the data
> contained in the response MUST NOT be used.

This document replaces the above requirement with the updated rule
in {{updated-rule}}.

## Updated Validation Rule {#updated-rule}

When a client retrieves protected resource metadata from a URL
obtained via the `resource_metadata` parameter in a WWW-Authenticate
challenge (as defined in Section 5 of {{RFC9728}}), the client MUST
verify ALL of the following conditions using the `resource` value
from the metadata response and the URL the client used to make the
request that triggered the challenge:

1. The scheme of the `resource` value MUST be `https`.

2. The host of the `resource` value MUST be identical (using
   case-insensitive comparison) to the host of the request URL.

3. The port of the `resource` value MUST be identical to the port
   of the request URL.  If either URL omits the port, the default
   port for the `https` scheme (443) MUST be used for comparison.

4. The path of the `resource` value MUST be a prefix of the path
   of the request URL, as defined in {{path-prefix-matching}}.

If any of these conditions are not met, the client MUST NOT use the
metadata, consistent with the security requirements of {{RFC9728}}.

Note that when the `resource` value is identical to the request URL,
all four conditions are trivially satisfied.  This means the updated
rule is fully backwards compatible with the original exact-match rule
in {{RFC9728}}: any metadata that was valid under the original rule
remains valid under this update.

## Unchanged: Validation for Well-Known URI Discovery

The validation rule in Section 3.3 of {{RFC9728}} for metadata
retrieved directly from a well-known URI (i.e., not via a
WWW-Authenticate challenge) is NOT changed by this document.
The `resource` value MUST still be identical to the protected
resource's resource identifier value from which the well-known URI
was derived, as specified in Section 3.3 of {{RFC9728}}.

## Path Prefix Matching {#path-prefix-matching}

This section defines the path prefix matching algorithm referenced
by condition 4 of the updated validation rule in {{updated-rule}}.

The path of the `resource` value is a prefix of the path of the
request URL if any of the following conditions hold:

1. The paths are identical (exact match).

2. The `resource` path ends with `/` and the request URL path starts
   with the `resource` path.  For example, a `resource` path of
   `/api/v1/` is a prefix of a request URL path of
   `/api/v1/accounts`.

3. The `resource` path does not end with `/`, and the request URL
   path is the `resource` path followed by `/` and optionally
   additional segments.  For example, a `resource` path of `/api/v1`
   is a prefix of request URL paths `/api/v1/` and
   `/api/v1/accounts`.

Matching MUST occur on segment boundaries.  A `resource` path MUST
NOT be treated as a prefix if the match would split a path segment.
For example, a `resource` path of `/api/v1` MUST NOT match a request
URL path of `/api/v10` or `/api/v1admin`, because `v10` and
`v1admin` are distinct path segments from `v1`.

Paths MUST be compared in their URI-normalized form per {{RFC3986}}.
Percent-encoded characters MUST be decoded before comparison.  An
empty or absent path MUST be treated as `/` for comparison purposes.

The following table illustrates the matching behavior:

| `resource` path | Request URL path         | Match?  |
|:----------------|:-------------------------|:--------|
| `/`             | `/accounts`              | Yes     |
| `/`             | `/api/v1/accounts`       | Yes     |
| `/api`          | `/api/v1/accounts`       | Yes     |
| `/api/`         | `/api/v1/accounts`       | Yes     |
| `/api/v1`       | `/api/v1/accounts`       | Yes     |
| `/api/v1`       | `/api/v1/`               | Yes     |
| `/api/v1/`      | `/api/v1/accounts`       | Yes     |
| `/api/v1`       | `/api/v1`                | Yes     |
| `/api/v1`       | `/api/v10`               | **No**  |
| `/api/v1`       | `/api/v1admin`           | **No**  |
| `/api/v1`       | `/api/v2/accounts`       | **No**  |
| `/api/v1`       | `/other`                 | **No**  |
| `/accounts`     | `/transactions`          | **No**  |

# Examples {#examples}

This section is non-normative.  It illustrates how the updated
validation rule in {{update-section-3-3}} applies in practice.

## Host-Level Resource Identifier

A resource server at `https://api.example.com` advertises a
host-level resource identifier covering all its protected resources.
When a client requests `https://api.example.com/transactions`
without a token:

~~~
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://api.example.com/
  .well-known/oauth-protected-resource"
~~~

The metadata response contains:

~~~ json
{
  "resource": "https://api.example.com/",
  "authorization_servers": ["https://as.example.com"],
  "scopes_supported": ["accounts.read", "transactions.read",
    "profile.read"],
  "bearer_methods_supported": ["header"],
  "resource_signing_alg_values_supported": ["RS256"]
}
~~~

Under the original Section 3.3 rule in {{RFC9728}}, this metadata
would be rejected because `https://api.example.com/` is not
identical to `https://api.example.com/transactions`.

Under the updated rule in {{updated-rule}}, the client validates
that `https://api.example.com/` shares the same TLS origin as
`https://api.example.com/transactions` (conditions 1-3) and that
the path `/` is a prefix of `/transactions` (condition 4).  All
checks succeed, so the client uses `https://api.example.com/` as
the `resource` parameter in its token request.

## Path-Level Resource Identifier

A resource server at `https://platform.example.com` exposes two
independent sets of protected resources under different path
prefixes.  When a client requests
`https://platform.example.com/api/v1/transactions` without a token:

~~~
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata=
  "https://platform.example.com/.well-known/
  oauth-protected-resource/api/v1"
~~~

The metadata response contains:

~~~ json
{
  "resource": "https://platform.example.com/api/v1",
  "authorization_servers": ["https://as.example.com"],
  "scopes_supported": ["transactions.read", "accounts.read"],
  "bearer_methods_supported": ["header"]
}
~~~

The client validates that `https://platform.example.com/api/v1`
shares the same TLS origin as
`https://platform.example.com/api/v1/transactions` (conditions 1-3)
and that the path `/api/v1` is a prefix of `/api/v1/transactions`
on a segment boundary (condition 4).  All checks succeed.

A subsequent request to
`https://platform.example.com/api/v2/reports` would NOT match the
resource `https://platform.example.com/api/v1` because `/api/v1` is
not a prefix of `/api/v2/reports` (condition 4 fails).  The client
would need to perform a separate discovery for the `/api/v2`
protected resources.

# Client Token Caching Guidance {#token-caching}

This section is non-normative.  It describes one approach clients
MAY use to take advantage of the relaxed resource matching rule.
Clients are not required to implement token caching; a client that
requests a fresh token for every protected resource access remains
fully compliant.

## Token Cache Key

A client that chooses to cache tokens MAY maintain a token cache
(informally, a "token jar") keyed by the tuple:

    (authorization_server, resource)

where:

- `authorization_server` is the issuer identifier of the
  authorization server from which the token was obtained.

- `resource` is the `resource` value from the protected resource
  metadata.

## Token Reuse Across Protected Resources

When a client needs to access a protected resource and already holds
a non-expired token in its cache, it MAY reuse that token if all of
the following conditions are met:

1. The client has previously retrieved protected resource metadata
   for the target protected resource (or another protected resource
   whose resource identifier's path is a prefix of the target URL's
   path on the same TLS origin) that contains the same `resource`
   value.

2. The cached token was obtained from the same authorization server
   identified in the metadata for the target protected resource.

3. The cached token has not expired and has not been revoked.

4. The scopes associated with the cached token are sufficient for
   the intended request, to the extent the client can determine
   this.

If any condition is not met, the client would need to perform a new
token request.

## Optimistic Token Reuse

A client that has discovered a resource identifier for one protected
resource MAY optimistically attempt to use a cached token when
accessing another protected resource whose URL path starts with the
`resource` path, even before performing metadata discovery for that
protected resource.  If the resource server rejects the token (e.g.,
with a 401 response), the client falls back to the standard
discovery flow for the new protected resource.

This optimistic reuse can reduce latency in common cases but does
not relax any security requirements.  The client should be prepared
for the token to be rejected and should not assume that all
protected resources under a given resource path prefix accept the
same token.


# Security Considerations

The security considerations of {{RFC9728}} (Section 7) continue to
apply in full.  This section describes how the updated validation
rule in {{update-section-3-3}} interacts with those considerations.

## Preservation of Origin Security Boundary

Section 7.3 of {{RFC9728}} describes impersonation attacks where
an adversary publishes metadata claiming to represent a legitimate
resource.  The updated validation rule in {{updated-rule}} maintains
the fundamental security property that prevents these attacks: the
TLS origin check (conditions 1-3) ensures that the `resource` value
is authoritative for the same server that issued the challenge.  An
attacker who controls `https://evil.example.com` cannot cause a
client to accept metadata with a `resource` value of
`https://api.example.com/`, because the origins differ.

## Path-Level Isolation

Some deployments host multiple independent services on the same
origin, distinguished only by path (e.g., a shared hosting
environment where `https://shared.example.com/serviceA` and
`https://shared.example.com/serviceB` are operated by different
tenants).  The path-prefix matching rule in this document supports
these deployments: each service can advertise its own path-scoped
resource identifier (e.g., `https://shared.example.com/serviceA`)
that covers only protected resources under that path prefix.

Resource servers in multi-tenant environments SHOULD use
path-specific resource identifiers that maintain the necessary
isolation between tenants.  A resource identifier of
`https://shared.example.com/serviceA` will not match requests to
`https://shared.example.com/serviceB/resource` because `/serviceA`
is not a path prefix of `/serviceB/resource`.  This ensures that
tokens obtained for one service cannot be inadvertently reused for
another service on the same origin.

## Token Scope and Audience

Relaxing the resource matching rule does not change the authorization
server's responsibility to enforce audience restrictions on issued
tokens.  The authorization server remains the authority on what
resource(s) a token is valid for.  A client's use of a resource
identifier (whether host-level or path-scoped) as the `resource`
parameter in a token request is a signal to the authorization server,
which MAY issue a token with a narrower or broader audience at its
discretion.

## Sender-Constrained Tokens

Deployments using sender-constrained tokens (e.g., DPoP {{RFC9449}})
are compatible with the relaxed matching rule defined in this
document.  The sender constraint binds the token to the client, not
to a specific protected resource, so token reuse across protected
resources on the same origin does not weaken the sender-constraint
security property.

## Metadata Substitution Within an Origin

The updated validation rule in {{updated-rule}} permits a protected
resource to direct clients to metadata with a `resource` value that
differs from the URL of the protected resource (but shares the same
origin and satisfies the path-prefix condition).  This means that a
compromised protected resource on an origin could direct clients to
metadata controlled by another protected resource on the same origin.
This risk is inherent to same-origin trust and is no different from
the existing web security model, where all content on the same
origin shares a trust boundary.  This risk also exists under the
original {{RFC9728}} rule, since a compromised protected resource
can already return arbitrary WWW-Authenticate challenges.


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

The authors would like to thank the members of the OAuth Working Group
for their feedback and discussion on the challenges of dynamic resource
discovery and cross-resource token reuse.

# Document History
{:numbered="false"}

-00

- Initial version.
