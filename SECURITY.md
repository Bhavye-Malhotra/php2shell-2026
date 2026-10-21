# Security Advisories (verbatim, published 2026-10-21 by php-src)

---

## GHSA-w8hw-w9fx-j79w — CVE-2026-109618 — RCE via OOM corruption

severity: critical | published: 2026-10-21T13:34:25Z

## Summary

PHP uses `longjmp()` for out-of-memory (OOM) errors to exit the current context and abort handling of the request. In some contexts, request memory is temporarily reachable before it is fully initialized. If any allocation fails at that point, PHP does not properly account for the early exit and leaves the request memory in an invalid state. The failed allocation does not need to be related to the invalid memory. The request shutdown procedure may then read or branch on it. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

## Vulnerability

### OOM strategies

Several multipart parsing problems can let a request reach OOM while remaining within its apparent PHP limits:

- A multipart request without a usable declared content length may pass the initial `post_max_size` check and continue supplying decoded body data.
- A multipart part can contain an unrestricted number of headers. Representing these headers inside PHP can use substantially more memory than their wire representation, allowing a request within `post_max_size` to exhaust the normal `memory_limit`.
- Empty file controls do not count towards `max_file_uploads` but still create the normal file metadata arrays. Nested field names multiply the generated array work.

OOM can also be reached in application-specific ways when attacker-controlled input causes a sufficiently large allocation or repeated memory use.

### Susceptibility

Apache mod_php unconditionally invokes the request shutdown procedure, even when request startup has failed. During request startup, automatic body parsing can exhaust the configured memory limit and exit the request in a context where state is temporarily invalid. Shutdown then processes this invalid state. This happens entirely before any application-specific code begins execution.

FPM exits the child when request startup fails. This prevents consumption of the invalid state and removes the child from the pool. After normal startup, OOM may still be reached in a context failing to account for an early exit, with the invalid state being processed during request shutdown. Source analysis therefore supports FPM as a susceptible, though no complete FPM exploit has been demonstrated for this SAPI.

Source analysis indicates that FrankenPHP, analogous to Apache mod_php, calls the request shutdown procedure unconditionally, making it likely susceptible to application-independent attacks. LSAPI models FPM, with application-specific exploits being likely but unvalidated.

## Mitigation

The patch removes `longjmp()` for OOM, avoiding an early exit out of contexts that do not properly account for it. It is replaced with a delayed, graceful soft OOM triggered at the next VM safe point, and an immediate hard OOM using `_exit()` if memory consumption reaches a second, higher threshold. The shutdown procedure will no longer see invalid state, and PHP's normal ability to limit memory consumption is retained.

> [!WARNING]
> Updating to a PHP release containing the patch to this vulnerability is the _only_ complete mitigation.

For installations that cannot update, setting and enforcing `memory_limit=-1` administratively is the primary configuration mitigation. It removes the predictable per-request limit that enables the confirmed exploit with a controllable OOM. This is not a complete mitigation. If `mmap()` or another underlying allocation fails, PHP can still use `longjmp()` while incomplete request memory is reachable. Restart every PHP worker and confirm that no pool, directory or application setting restores a finite PHP memory limit.

Keep `post_max_size` conservative and independently enforce the decoded request size at the frontend. Reduce `max_input_nesting_level`, and bound the number of input variables, multipart parts, headers within each part and uploads. These controls reduce hard OOM and denial of service risk even after applying the patch, but do not replace updating. If the application does not use multipart form data, block such requests at the frontend before they reach PHP.

A container or cgroup memory limit (`memory.max`) may provide an alternative to PHP's own `memory_limit` with some limitations. It is not guaranteed to prevent allocation failure and is not a complete mitigation. For example, killing a container or cgroup can also kill the master and every worker, unless each worker has its own group. Killing one FPM child fails only its current requests and FPM's master replaces it quickly. Do _not_ use `RLIMIT_AS` or `RLIMIT_DATA`, as these will cause `mmap()` to fail once the memory limit is reached, triggering the vulnerable `longjmp()` path.

**Important**: Make sure to also follow the remediation advice from the related report.
https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp

## Impact and reliability

The confirmed impact is unauthenticated remote code execution as the web worker account. Complete remote code execution was validated over HTTP against mod_php with default PHP input and memory limits and normal prefork configurations with multiple workers. Additional workers and unrelated traffic can increase the required number of attempts but do not remove the condition. Exploit portability and reliability depend on the PHP build, extensions, frontend behavior and allocator layout.


---

## GHSA-6wmf-4rv5-p3rp — CVE-2026-109619 — RCE via stale global state

severity: critical | published: 2026-10-21T13:34:13Z

## Summary

PHP contains various global state, such as error, session, object and extension state that is retained by a worker but points to memory owned by one request. That state must be reset before the request memory is released. Some input, configuration, session and error handling operations run before normal initialization of the next request. They inadvertently access stale state not reset by the previous request before initialization has a chance to replace it, causing a use after free. A strategically crafted heap layout can produce full remote code execution (RCE).

State can survive for more than one reason. A fatal error, including one caused by memory exhaustion, can abandon an operation before it performs its matching reset. A warning or other nonfatal diagnostic can also repopulate error state after that state was already cleared during shutdown. The request heap is then freed while the worker global field still refers to it. A later operation that runs before normal request initialization can consume the stale value.

Successful exploitation of this vulnerability requires both a producer and a consumer. The producer is a PHP operation that stores state owned by one request in a location PHP can access later in a subsequent request. The consumer is a subsequent PHP operation that reads, frees, branches or otherwise acts on the stale state previously stored by the producer.

A concrete vulnerability would arise under the following conditions:

1. A reachable PHP operation stores request-owned state in a globally accessible location, acting as the producer.
2. The state is not reset, or another operation repopulates it after its normal reset.
3. PHP releases the request memory while the persistent worker retains the referring global state.
4. The same worker handles another request.
5. A PHP operation reads, frees, branches or otherwise acts on the stale state before normal request initialization resets it, acting as the consumer.

The demonstrated producing and consuming operations occur in different HTTP requests handled by the same worker. The exact affected versions, configuration and mitigations depend on the internal state affected by the producing operation.

## Vulnerability

### Producers

A producing operation becomes dangerous when its request-owned state remains published after the request heap is freed. A fatal error can cause this by abandoning the operation before it resets the state. Fatal interruptions include parse and compile failures, uncaught errors, failure of `require`, and `Maximum execution time exceeded`.

OOM can provide the same interruption when an affected error, exception, object or extension state was already published.

Even a nonfatal diagnostic from extension or server cleanup during a later shutdown stage can repopulate new request-owned error information to the global state.

### Consumers

There are two confirmed consumers before normal initialization.

#### INI diagnostics before request initialization

A warning, notice or deprecation during initialization can consume stale error state. It does not need to be fatal, displayed or logged. Such a warning may be raised when applying invalid or deprecated INI settings before ordinary executor initialization. Examples include:

- Deterministic deprecations such as `auto_detect_line_endings=1`, a `filter.default` value other than the default, PHP 8.3+ legacy `assert.*` settings, PHP 8.4+ legacy session settings, and PHP 8.5 `report_memleaks=0` or nonzero `intl.error_level`.
- Explicitly configured `mbstring.http_input`, `mbstring.http_output`, `mbstring.internal_encoding`, `iconv.input_encoding`, `iconv.output_encoding` or `iconv.internal_encoding`.
- Invalid or conflicting `zend.assertions`, `memory_limit`, `date.timezone`, DBA, EXIF, mail, OpenSSL, zlib and loaded extension values.
- Malformed or overflowing quantities, including invalid `memory_limit`, body size, input, timeout, stack and extension values on PHP 8.2+.
- Configured log, mail, session or SOAP cache paths rejected under `open_basedir`.

Global state is accessed before PHP decides whether to report, display or log the warning. Changing `error_reporting`, using `@`, or disabling `display_errors` or `log_errors` does not protect against this vulnerability.

##### Reachability

With Apache mod_php, `.htaccess` and Apache `php_value`/`php_flag`/`php_admin_*` directory configuration is applied before `php_request_startup()`. Normal `php.ini` is startup configuration and is not reapplied as a consumer across requests.

FPM is conditionally exposed when nginx, Apache `mod_proxy_fcgi` or another frontend sends `PHP_VALUE`/`PHP_ADMIN_VALUE` parameters that produce a diagnostic before request initialization. FPM pool values are applied when a worker starts, and `.user.ini` is applied after normal initialization. They do not provide the same early consumer. FPM also exits a child after `php_request_startup()` returns failure.

LSAPI can apply special environment INI values early and is a conditional candidate. An equivalent early configuration consumer was not established in the default configuration of FrankenPHP. This does not make this environment immune. It may expose different consumers through application or extension behavior.

#### Session upload progress before normal initialization

Session upload progress can reach session handling before ordinary session initialization. It can therefore consume session or decoder state left by an interrupted request before normal initialization resets it. This consumer is independent of the INI diagnostic path and does not require a diagnostic from configuration.

## Concrete and candidate cases

### PHP 8.5 fatal error backtrace: confirmed

With `fatal_error_backtraces` enabled, fatal error reporting stores backtrace state owned by the request. Resetting of this global state is always missed during shutdown. A diagnostic on a subsequent request reaches the stale value before normal request initialization resets it.

This is the strongest demonstrated case and is the basis of the confirmed mod_php exploitation.

### Session upload progress lifecycle: confirmed

An upload can initialize request-owned session and decoding state before normal module initialization. OOM or another fatal error after that state has been published can prevent its matching reset. PHP then frees the request heap while persistent session or decoder globals still refer to it. A later upload progress operation reaches those globals before ordinary initialization and treats them as valid state.

The demonstrated application-independent trigger is OOM during input processing. Other fatal errors at this stage can cause the same state transition, but generally require additional application, extension or configuration conditions.

With mod_php, both the producing operation and fatal error can occur during multipart startup. FPM terminates a child when this startup fails, so that exact sequence does not survive. The validated FPM path instead publishes state during application execution after successful startup, reaches a fatal error, and then uses session upload progress as the early consumer. It works with a normal dynamic FPM pool, although it depends on a suitable application operation.

Session upload progress is enabled by default, and no application call to `session_start()` is required. It can supply a producer, consumer or both, but exploitation still requires an interruption after state is published and a subsequent request handled by the same worker.

### Other error, exception, object and extension state: conditional

Supported PHP branches contain other request state that may become unsafe after a request boundary. The complete patch resets this wider state because it must not survive into operations that precede normal initialization. Whether it is reachable depends on the application, extensions and the exact point where the state was published.

Fatal errors inside PHP operations that call back into an application deserve particular attention. The callback may introduce a fatal error while the operation still has temporary state. Applicability depends on a route reachable by an attacker, the callbacks registered by that application or extension, and a later consumer before normal request initialization. There is no configuration based mitigation that covers every such operation.

## Mitigation

> [!WARNING]
> Updating to a release containing the complete state reset patch is the only reliable mitigation. **There is no complete generic configuration mitigation as an application, extension or server path may publish stale state or consume it without a predictable log entry.**

For PHP 8.5 installations that cannot update, set `fatal_error_backtraces=0` administratively and restart every worker. This removes the producer used by the confirmed RCE case. It does not cover other request-owned global or extension state.

For the session lifecycle case, set `session.upload_progress.enabled=0` administratively and restart every worker. This prevents the demonstrated early session producing and consuming operations. It does not mitigate the other lifecycle paths. It might be prudent to set `session.upload_progress.enabled=0` if you don't need this feature even after applying the patch, as more attackers try to find flaws in this hardly-used and hardly-tested feature.

Reduce the remaining risk by breaking as many links in the lifecycle as possible:

1. Eliminate fatal errors on paths reachable by an attacker. Include failures that depend on request flow in upload, import, error page, shutdown, destructor, serialization, output handler, plugin and extension paths rather than only failures seen during ordinary page requests.
2. Eliminate warnings and other diagnostics emitted during extension post-deactivation and server cleanup, after normal request error state has already been cleared.
3. Eliminate diagnostics from all INI configuration applied before request initialization. Prefer `php.ini`, FPM pool or server configuration applied at startup over per request overrides, and remove obsolete directives.
4. If performance is not a factor, consider limiting the number of requests a worker may execute using `pm.max_requests=1`.

A PHP execution timeout should be treated like another fatal error. Prevent attacker controlled requests from predictably reaching `Maximum execution time exceeded` while PHP is inside an affected operation. Changing the time limit only removes that possible interruption and does not mitigate the other cases.

### Logging and configuration audit

Enable `log_errors=On`, a functional `error_log`, and `error_reporting=E_ALL` in startup configuration during an isolated audit. Review Apache, PHP-FPM, reverse proxy and service logs for:

- Warnings, deprecations and core errors repeated before target scripts run.
- Warnings and other diagnostics produced during extension or server cleanup.
- Fatal, parse and uncaught error messages.
- `Maximum execution time exceeded`.
- Failures restricted to routes, content types, files, callback implementations or plugin options controlled by an attacker.

Fixing observed errors reduces exposure, but absence of an error in logs is not proof of safety. Historical logs may have been collected with deprecations or other relevant severities excluded. Even an audit using `E_ALL` only covers the routes and application states that were exercised. A failure may also happen before PHP writes the message. Logs must supplement a static configuration and application flow audit.

**Important**: Make sure to also follow the remediation advice from the related report.
https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w

## Impact and reliability

The confirmed impact is unauthenticated heap use-after-free, memory disclosure and remote code execution with the web worker's privileges. The fatal backtrace path has confirmed RCE against mod_php. Session lifecycle RCE was validated against mod_php and FPM. Other state families establish security impact only after a concrete producer and consumer are shown.

The producer and consumer requests must reach the same worker. Multiple workers and recycling reduce success per request but do not remove the condition.


