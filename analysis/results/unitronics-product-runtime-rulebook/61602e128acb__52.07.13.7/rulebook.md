# PRODUCT_RUNTIME Rulebook v1

## Scope and stop condition

This rulebook classifies an installed binary package or directly observed SBOM
component as one of:

- `PRODUCT_RUNTIME`
- `NON_PRODUCT_RUNTIME`
- `REVIEW_REQUIRED`

The unit of decision is the binary package/SBOM component, never its `Source`.
The rulebook stops after runtime-role classification and upstream identity
identification. It does not query or assign a CPE, inspect NVD Configuration,
analyze CVEs, normalize versions, or create Ground Truth records.

The following fields are explicitly prohibited as runtime evidence:

- Original SBOM CPE
- installed control `CPE-ID`

They were not read into the representative decision records.

## Operational definition

`PRODUCT_RUNTIME` means that the exact installed package/component directly
contains an implementation that upstream defines as performing the software
product's characteristic runtime function. Qualifying implementations are:

1. a canonical executable that performs the defining product operation;
2. a primary daemon that implements the defining protocol/service;
3. a core runtime library that upstream explicitly presents as a principal
   implementation/API of the product; or
4. an implementation unit that is demonstrably indispensable to that product
   runtime on the observed platform.

The term *canonical executable* does not include every command shipped by an
upstream project. A configuration, monitoring, orchestration, or development
client is not included merely because it is official or commonly installed.

`NON_PRODUCT_RUNTIME` means that sufficient evidence identifies the component
as an accessory or packaging construct rather than the selected upstream
product's characteristic runtime implementation. Typical cases are optional
plugins, extensions, providers, helpers, configuration/data-only packages,
meta/virtual packages, kernel modules, and firmware/board data.

`REVIEW_REQUIRED` means that the available exact-firmware and official upstream
evidence support competing interpretations of the product/runtime boundary, or
that upstream identity cannot be confirmed. It is an intended output, not a
failed classification.

## Non-inheritance invariants

The following implications are invalid:

```text
same Source      => same product identity
same Source      => same PRODUCT_RUNTIME status
Source basename  == package name => PRODUCT_RUNTIME
main-like package exists          => siblings inherit its status
library payload                   => PRODUCT_RUNTIME
CLI payload                       => NON_PRODUCT_RUNTIME
```

One Source may produce zero, one, or several `PRODUCT_RUNTIME` packages. Every
package must independently pass the decision flow.

## Evidence hierarchy

### E1 — exact-firmware package/artifact evidence

Use, in descending order:

- `/usr/lib/opkg/info/<package>.control`
- `/usr/lib/opkg/info/<package>.list`
- `/usr/lib/opkg/status`
- direct binary/artifact traceability for a non-opkg SBOM component

Required checks are package, version, Source/SourceName, description,
dependencies, status match, actual listed payload, and representative paths.
An empty `.list` does not halt the flow, but it prevents payload-positive
classification and normally lowers evidence strength.

### E2 — sibling-package structure

Inspect all packages from the same exact `Source` to identify splits such as
main runtime, shared library, CLI, plugin, module, helper, configuration, and
meta package. Siblings are relational context only; they never transfer status.

### E3 — official upstream evidence

Use official documentation, official manuals, and the official source
repository to establish:

- the upstream software identity;
- the product's defining runtime function;
- whether an executable is the product interface or only a management client;
- whether a library is a principal product implementation or a support library;
- whether a plugin is optional, alternative, or indispensable on the observed
  platform.

Blogs, package-index summaries, CPE records, and search-result snippets are not
decision evidence.

## Decision flow

Apply the questions in order and retain the evidence used at every terminal
decision.

### Q1. Is upstream identity reproducible?

Can exact `Source`/`SourceName`, package metadata, and official upstream material
identify the upstream software boundary?

- No: `REVIEW_REQUIRED`.
- Yes: continue.

### Q2. Is exact installed ownership reproducible?

Does `.list` or direct artifact traceability show the owned executable, daemon,
library, module, configuration, or other payload?

- Yes: continue with normal strength.
- Empty `.list`: continue only when description, dependency, and sibling
  structure identify a packaging construct; never infer a positive runtime
  payload from Source alone.
- Conflicting/missing ownership: `REVIEW_REQUIRED`.

### Q3. What upstream product boundary is being tested?

State the product boundary in the record before deciding status. A library with
its own official identity must not silently inherit the identity of a larger
suite, and a suite name must not be assigned to a partial library simply because
they share a repository.

If the boundary itself remains materially ambiguous: `REVIEW_REQUIRED`.

### Q4. Does the payload directly implement the defining product function?

Positive evidence requires both:

1. exact ownership of an executable, primary daemon, or runtime library; and
2. official upstream evidence that this payload is a canonical implementation,
   not just a file shipped by the project.

If both are true, continue to Q5. Otherwise continue to Q6.

### Q5. Is there an accessory/split exclusion?

Do exact and upstream evidence identify the package as configuration-only,
meta/virtual, helper, optional plugin/provider/extension, development-only,
localization/data-only, kernel module, or firmware/board data?

- No: `PRODUCT_RUNTIME`.
- Yes and the accessory role is unambiguous: `NON_PRODUCT_RUNTIME`.
- Yes, but the unit may be indispensable to the runtime architecture: continue
  to Q7.

### Q6. Is it a non-core suite/library/control component?

- A support library used by canonical executables but not itself established as
  a principal upstream product implementation is `NON_PRODUCT_RUNTIME`.
- A control/monitor/configuration client that does not implement the defining
  service is `NON_PRODUCT_RUNTIME`.
- A partial library whose official role is core-like while the upstream suite
  boundary is program-centric is `REVIEW_REQUIRED`.
- Otherwise: `NON_PRODUCT_RUNTIME` when accessory evidence is sufficient;
  `REVIEW_REQUIRED` when it is not.

### Q7. Pluginized mandatory-runtime exception

Names such as `plugin`, `provider`, or `module` never establish the exception.
All three conditions are required:

1. official architecture identifies the unit as a required runtime port/backend
   for the observed platform or mode;
2. exact dependencies/configuration show that this implementation is selected;
3. no equivalent alternative is active, or the package is the observed unit
   providing the indispensable function.

- All three proven: `PRODUCT_RUNTIME` may be assigned with a written exception.
- Optional/alternative capability proven: `NON_PRODUCT_RUNTIME`.
- Core-looking function but mandatory/selected state not fully proven:
  `REVIEW_REQUIRED`.

## Inclusion criteria

Use `PRODUCT_RUNTIME` only when a record satisfies one of these patterns:

| Pattern | Required evidence |
|---|---|
| Canonical functional CLI | Exact executable plus official manual showing that the executable itself performs the product's defining operation |
| Primary daemon | Exact daemon/core library plus official architecture identifying it as the service/protocol engine |
| Principal runtime library | Exact shared library plus official upstream material defining that library as a principal implementation/API of the product |
| Direct kernel image | Direct binary traceability to the resident kernel image plus official kernel identity |
| Mandatory pluginized runtime | All Q7 conditions, with the exception explicitly recorded |

Examples validated in this dry-run include `openssl`, `libssl`/`libcrypto`,
`curl`, `libcurl`, `iptables`/`ip6tables`, `charon`/`libcharon`, e2fsprogs
filesystem-creation utilities, and the directly observed Linux kernel image.

## Exclusion criteria

Use `NON_PRODUCT_RUNTIME` when exact and official evidence establish one of:

- configuration/init files without the implementation;
- an optional or alternative provider/plugin/extension;
- a helper or generic support library, rather than the named suite/product's
  principal runtime;
- a metadata-only or dependency-only package;
- a virtual package with no owned runtime payload;
- a loadable kernel module when evaluating Linux parent identity;
- a management/control frontend that does not itself implement the defining
  service.

`NON_PRODUCT_RUNTIME` is scoped to the `upstream_product` boundary written in
the record. For example, excluding a Linux `kmod-*` from Linux parent identity
does not decide whether the module implements a separately named upstream
product.

## REVIEW_REQUIRED triggers

Mandatory review is required for:

1. upstream identity not reproducibly confirmed;
2. exact payload ownership missing or contradictory;
3. official sources support two plausible product boundaries;
4. pluginized architecture where the plugin supplies a core port/backend but
   exact mandatory/selected state is incomplete;
5. dynamically split suite library required by installed executables while
   upstream documentation treats the suite primarily as programs/utilities;
6. ambiguous management CLI that may itself be a separately identified product;
7. strength `WEAK` for any proposed positive classification.

## Evidence strength

Evidence strength is independent of Ground Truth Decision and CPE availability.

- `STRONG`: exact status/version match and payload ownership, plus direct
  official upstream role evidence; or exact empty-payload metadata conclusively
  proving a meta/virtual construct.
- `MODERATE`: exact metadata and payload/sibling evidence are present, but the
  official product boundary or mandatory-runtime property requires inference;
  also used for clear empty-list extension packages.
- `WEAK`: upstream identity, payload ownership, or role rests on indirect
  evidence. A `WEAK` positive must be converted to `REVIEW_REQUIRED`.

## Automation record requirements

Every automated record must contain at least:

```text
source
package
version
description
installed_payload_summary
representative_paths
sibling_packages
existing_package_role
upstream_product
official_upstream_evidence
runtime_role
product_runtime_status
decision_reason
evidence_strength
```

It must also preserve whether the evidence came from control+list+status,
control-only because the list was empty, or direct non-opkg artifact
traceability.

## Deterministic pseudocode

```text
if upstream_identity_not_confirmed:
    REVIEW_REQUIRED
elif exact_ownership_conflicts:
    REVIEW_REQUIRED
elif meta_or_virtual_or_config_only:
    NON_PRODUCT_RUNTIME
elif kernel_module_for_linux_parent_boundary:
    NON_PRODUCT_RUNTIME
elif plugin_or_provider:
    if optional_or_alternative:
        NON_PRODUCT_RUNTIME
    elif mandatory_selected_runtime_port_is_fully_proven:
        PRODUCT_RUNTIME  # written exception required
    else:
        REVIEW_REQUIRED
elif management_or_control_cli_only:
    NON_PRODUCT_RUNTIME
elif canonical_functional_executable_or_primary_daemon:
    PRODUCT_RUNTIME
elif official_principal_runtime_library:
    PRODUCT_RUNTIME
elif partial_suite_library_with_competing_boundary_evidence:
    REVIEW_REQUIRED
else:
    NON_PRODUCT_RUNTIME if accessory_role_is_proven else REVIEW_REQUIRED
```

## Official upstream evidence registry

The dry-run uses these primary sources. Descriptions below are paraphrases.

- `UP-OPENSSL-SSL`: OpenSSL 3.0 documents `ssl` as the SSL/TLS library and its
  protocol API: <https://docs.openssl.org/3.0/man7/ssl/>
- `UP-OPENSSL-CRYPTO`: OpenSSL 3.0 documents `crypto` as its cryptographic
  library: <https://docs.openssl.org/3.0/man7/crypto/>
- `UP-OPENSSL-CLI`: OpenSSL documents `openssl` as the command-line program for
  the toolkit's cryptographic functions:
  <https://docs.openssl.org/3.0/man1/openssl/>
- `UP-OPENSSL-LEGACY`: OpenSSL documents the legacy provider as a provider of
  algorithms classified as legacy:
  <https://docs.openssl.org/3.0/man7/OSSL_PROVIDER-legacy/>
- `UP-CURL-DOCS`: curl's official documentation separates and documents both
  the command-line tool and libcurl: <https://curl.se/docs/>
- `UP-CURL-CLI`: the official manual defines curl as a URL-transfer command:
  <https://curl.se/docs/manpage.html>
- `UP-LIBCURL`: the official API documentation defines libcurl as the transfer
  library/API: <https://curl.se/libcurl/c/>
- `UP-IPTABLES`: netfilter.org defines iptables as the userspace command-line
  program and explicitly includes ip6tables in the project:
  <https://www.netfilter.org/projects/iptables/index.html>
- `UP-IPTABLES-EXT`: netfilter's official HOWTO describes command extensions as
  shared libraries loaded to add tests/targets:
  <https://www.netfilter.org/documentation/HOWTO/packet-filtering-HOWTO-7.html>
- `UP-STRONGSWAN-CHARON`: strongSwan 5.9 documents charon as its IKEv2 daemon
  and libcharon as containing most daemon-core code:
  <https://docs.strongswan.org/docs/5.9/daemons/charon.html>
- `UP-STRONGSWAN-DEVS`: official component documentation identifies
  libstrongswan as the basic library used by daemons and utilities:
  <https://docs.strongswan.org/docs/latest/devs/devs.html>
- `UP-STRONGSWAN-PLUGINS`: strongSwan 5.9 describes its plugins as extended or
  specialized features around a small core:
  <https://docs.strongswan.org/docs/5.9/plugins/plugins.html>
- `UP-STRONGSWAN-SWANCTL`: official documentation defines swanctl as a utility
  to configure, control, and monitor charon through VICI:
  <https://docs.strongswan.org/docs/latest/swanctl/swanctl.html>
- `UP-STRONGSWAN-VICI`: official documentation defines VICI as an external
  control/configuration interface and notes that it can be disabled:
  <https://docs.strongswan.org/docs/5.9/plugins/vici.html>
- `UP-STRONGSWAN-PLUGIN-LOAD`: official loading documentation confirms modular
  compile-time/runtime plugin selection:
  <https://docs.strongswan.org/docs/latest/plugins/pluginLoad.html>
- `UP-E2FSPROGS-README`: the upstream repository defines e2fsprogs as extended
  filesystem management programs:
  <https://raw.githubusercontent.com/tytso/e2fsprogs/v1.47.0/README>
- `UP-E2FSPROGS-MKE2FS`: the version-matched official manual defines mke2fs and
  its mkfs.ext2/3/4 invocation modes:
  <https://raw.githubusercontent.com/tytso/e2fsprogs/v1.47.0/misc/mke2fs.8.in>
- `UP-E2FSPROGS-INSTALL`: the upstream install document distinguishes program
  installation from optional include/library installation:
  <https://raw.githubusercontent.com/tytso/e2fsprogs/v1.47.0/INSTALL>
- `UP-E2FSPROGS-EXT2FS`: the version-matched upstream source exposes the
  libext2fs filesystem-access API:
  <https://raw.githubusercontent.com/tytso/e2fsprogs/v1.47.0/lib/ext2fs/ext2fs.h>
- `UP-UTIL-LINUX`: the official repository describes util-linux as a collection
  of Linux utilities and contains libblkid/libuuid as subdirectories:
  <https://raw.githubusercontent.com/util-linux/util-linux/v2.36.1/README>
- `UP-UTIL-LINUX-BUILD`: the version-matched official build definition exposes
  libblkid and libuuid as separately versioned libraries inside util-linux:
  <https://github.com/util-linux/util-linux/blob/v2.36.1/configure.ac>
- `UP-LINUX`: the official Linux source documentation identifies Linux as the
  kernel and describes the resident image:
  <https://github.com/torvalds/linux/blob/v5.15/Documentation/admin-guide/README.rst>
- `UP-LINUX-KBUILD`: kernel documentation distinguishes the resident `vmlinux`
  image from loadable modules:
  <https://docs.kernel.org/kbuild/makefiles.html>

## Versioning note

This is Rulebook `v1`, validated only against the representative cases in this
directory. Any change to the operational definition, terminal flow, or mandatory
plugin exception requires a new rulebook version before a 582-component run.
