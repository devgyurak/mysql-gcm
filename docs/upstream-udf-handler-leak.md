# Upstream report draft — a failed re-prepare leaks every loadable function the prepared statement had already fixed

**Status: a draft. Not submitted anywhere.** It records what `mysql-gcm` found while building on the
loadable-function API (issue #43) so that the finding has one home in the repository. Sending it, in
whole or in part, is a separate, deliberate act for a human to take, and no text here may be pasted
into another tracker as if it were a filed report.

The finding is about **MySQL**, not about this component. The component cannot detect it, prevent it,
or work around it from inside; what it does instead is give up its own secrets on the error row
(`docs/design.md` amendment A16), which covers the instance that raises and no other.

## Summary

When a prepared statement's re-prepare — its `EXECUTE` — fails **after** a loadable function has been
fixed, every such function's `udf_handler` is abandoned: its `UDF_INIT` is never passed to the function's
de-initialisation function, and the `udf_func::usage_count` that `find_udf()` incremented is never
given back. The second one has a user-visible consequence — a component that registered those
functions can no longer be uninstalled (or replaced) until the server restarts, because
`mysql_udf_registration::udf_unregister` succeeds only while `usage_count == 1`, and the server then
reports `ERROR 3538 (HY000): De-initialization method provided by component '<name>' failed.`

The first shape found, and the one this issue was filed with, is a function that is the argument of
another and takes a prepared-statement parameter — but **the nesting, the parameter and the raised
error are all incidental**. What the leak needs is the failed fix, and it drops:

- a *sibling* function in the same select list,
- a key-id function that **raises nothing** (it sealed successfully while the outer function's init
  evaluated it) — its seal is then never folded into the usage count either,
- and a plain prepared statement invalidated by `ALTER TABLE`, with no nesting and no parameter at
  all.

Reproduced on **8.0 (8.0.46), 8.4 (8.4.11) and 9 (9.4.0)**; the source read is against the 8.0.43,
8.4.11 and 9.4.0 trees.

## Where the code says so

Paths are for 8.4.11; the file and function names are the same in 8.0.43 and 9.4.0. Each statement
was read from the sources of all three trees; the two places where the versions differ are called out.

1. `sql/item_func.cc`, `udf_handler::fix_fields()` — the handler takes a reference:

   ```cpp
   udf_func *tmp_udf = find_udf(u_d->name.str, (uint)u_d->name.length, true);
   ...
   m_initialized = true;  // Use count was incremented by find_udf()
   ...
   class cleanup_guard { ... ~cleanup_guard() { m_udf->clean_buffers(); m_udf->free_handler(); } void defer() ... }
     udf_fun_guard(this);
   ```

   `find_udf(name, len, /*mark_used=*/true)` does `udf->usage_count++` (`sql/sql_udf.cc`), and
   `free_handler()` → `free_udf()` does `--udf->usage_count`.

   The RAII guard is the release path for a failure *inside this call* — but the code **defers** it
   as soon as the handler is worth keeping:

   ```cpp
   if (is_in_prepare && !initid.const_item) { udf_fun_guard.defer(); return false; }
   if (u_d->func_init) {
     if (call_init_func()) return true;
     ...
   }
   udf_fun_guard.defer();   // "UDF initialization complete so leave the freeing up resources to cleanup method."
   return false;
   ```

   After either `defer()`, only `udf_handler::cleanup()` can release the handler.

2. `sql/item_func.cc`, `udf_handler::call_init_func()` — one way for the fix to fail, and the one the
   first shape uses. A constant argument is evaluated during init:

   ```cpp
   if (args[i]->const_for_execution() && !args[i]->has_subquery()) {
     switch (args[i]->result_type()) {
       case STRING_RESULT:
       case DECIMAL_RESULT: {
         get_string(i);                      // -> args[i]->val_str(...)
         if (thd->is_error()) return true;   // 8.4.11 and 9.4.0 only
         break;
       }
       ...
   ```

   `get_string()` calls `args[index]->val_str(...)`. For an argument that is itself an `Item_udf_func`
   that goes to `udf_handler::val_str()` → `get_arguments()` → the inner function's row callback,
   which sees the parameter as empty (the values are bound after the re-prepare) and raises.

   **Version difference 1:** 8.0.43 has no `if (thd->is_error()) return true;` after those
   evaluations; 8.4.11 and 9.4.0 do. 9.4.0 additionally requires `!args[i]->has_stored_program()`.
   That is why 8.0 leaks the *outer* function's handler too, where the other two abort before calling
   its init.

   The same leak follows any other failure of the **re-prepare** that happens after a function has
   been fixed — `ALTER TABLE` invalidating a prepared statement is the simplest one, because it needs
   no loadable function inside another and no parameter. What the trigger does *not* include was
   measured too: a re-prepare that fails **before** the function is fixed (its failing column first in
   the field list) leaks nothing, and a plain, unprepared statement's fix failure was not observed to
   leak — only the re-prepare path enters the state `udf_handler::cleanup()` returns early from.

3. `sql/item_func.cc`, `udf_handler::cleanup()` — the only releaser of a deferred handler, and it
   deliberately does nothing while a (re-)prepare is in progress:

   ```cpp
   void udf_handler::cleanup() {
     if (!m_original || !m_initialized) return;

     clean_buffers();
     /*
       Make sure to not free the handler from the cleanup() call when
       (re)preparing the UDF function call. The handler allocated by
       udf_handler::fix_fields() will be used in execution.
     */
     THD *thd = current_thd;
     if (thd->stmt_arena->is_stmt_prepare() && thd->stmt_arena->is_repreparing)
       return;

     if (m_init_func_called && u_d->func_deinit != nullptr) {
       (*u_d->func_deinit)(&initid);
       m_init_func_called = false;
     }
     DEBUG_SYNC(current_thd, "udf_handler_destroy_sync");
     free_handler();
   }
   ```

   The early return is correct when the re-prepare succeeds — the handler is about to be used by the
   execution. It is the problem when the re-prepare **fails**: no execution follows, so nothing
   revisits the handler, and the early return has already skipped the release.

4. `sql/item_func.cc`, `Item_udf_func::cleanup()` → `udf.cleanup()` is the only route to that release
   for a fixed item, and `~Item_udf_func() override = default;` in `sql/item_func.h` (same in all
   three trees) means destroying the item releases nothing. A statement that failed during fix or
   re-prepare discards the item tree without a cleanup pass, so the deferred handler is lost with the
   `MEM_ROOT`.

5. `sql/sql_udf.cc`, `mysql_udf_registration_imp::udf_unregister()` — the observable consequence:

   ```cpp
   if (!udf->dl && !udf->dlhandle &&  // Not registered via CREATE FUNCTION
       (udf->usage_count == 1))       // Not used
   ```

   A component-registered function sits at `usage_count == 1` when idle. One leaked handler leaves it
   at 2 or more, so unregister fails, and a component whose de-initialisation then refuses (as
   `mysql-gcm`'s does, to avoid freeing a live `UDF_INIT`) makes `UNINSTALL COMPONENT` fail with
   ER 3538.

## The sequence, in the nested shape

1. `PREPARE s FROM 'SELECT outer(inner(?, ?), ?)'` — the first prepare fixes the inner item (its
   `init` may be deferred) and the outer's handler is left deferred for execution.
2. `EXECUTE` re-prepares (`is_repreparing`). The item cleanup runs first and early-returns (point 3),
   keeping both handlers.
3. Re-fixing the outer calls `udf_handler::fix_fields` for the inner as well, which takes a **second**
   use-count reference and calls the inner's `init`. (Source read: `find_udf(name, len, true)`
   increments `usage_count` at the top of `udf_handler::fix_fields`; the probe's counts show the
   repeated `init`s but cannot separate the reference from them.)
4. The outer's own `call_init_func` then treats the inner as a constant argument and evaluates it
   (point 2) — the parameters have no values yet at this point.
5. The inner's row callback raises. In 8.4.11/9.4.0 `call_init_func` notices `thd->is_error()` and
   returns true **before** calling the outer's `init`; the outer's guard is still active and releases
   the outer's handler. The inner's handler was already deferred, so nothing releases it.
6. In 8.0.43 the missing check lets the outer's `init` run anyway; `udf_fun_guard` is then deferred
   and `Item_udf_func::fix_fields` aborts on its own `if (thd->is_error()) return true;` — so the
   outer's handler leaks too.
7. The item tree is discarded. No de-init function runs for the leaked handlers, and no use count is
   returned.

The `ALTER TABLE` shape is the same thing with steps 3 and 4 replaced by "the re-prepare fails while
resolving the field list": the promise of an execution that would have released the handler is broken
the same way.

## The shapes, measured

The repository's test-only probe component counts its own `init` and `deinit` calls
(`tests/probe/probe.cc`, run by `scripts/verify-nested.sh`), and `tests/integration/nested` records
one expected output per major:

| Case | Shape | Result on 8.4/9 (8.0 where it differs) |
|:--|:--|:--|
| `20` | `probe_outer(probe_raise_volatile(?, ?), ?)`, prepared, two `EXECUTE`s | inner `init` 2, `deinit` 0; `UNINSTALL COMPONENT` refused (8.0: outer `init` 2 as well) |
| `26` | the same with the probe's `const_item` variant | the same counts — constness changes nothing |
| `23` | `probe_outer(?), probe_outer(probe_raise_volatile(?, ?), ?)` — a sibling, no nesting | the sibling's `init` has no `deinit`; uninstall refused (8.0: one more init) |
| `24` | a key-id seal that succeeds inside an outer function, another item raising | the seal is never counted (`random_seals` 0, then 1 after a plain seal) and `UNINSTALL COMPONENT gcm` is refused (8.0: one more init) |
| `25` | `PREPARE 'SELECT probe_outer(d), c FROM nested_t'` → `EXECUTE` → `ALTER TABLE … DROP COLUMN c` → `EXECUTE` | `init` 2, `deinit` 1 — one leaked — uninstall refused, identical on all three. The control with the failing column first (`SELECT c, probe_outer(d)`) adds no init |
| `21`, `22` | the probe with literal arguments, or a `?` on a direct call | every `init` paired with its `deinit`; uninstall succeeds |

`24` is the one worth reading twice: the dropped instance had done real work and held a key read from
the keyring. Nothing wiped it, and the usage count it should have folded (design A14) is simply gone
— a count is a lower bound for exactly this reason.

## Reproducer

Self-contained: one component with two functions and a counter, no keyring and no cryptography.

- Component: `tests/probe/probe.cc` in `mysql-gcm` (uses only `udf_registration` and
  `mysql_runtime_error`). `probe_raise_volatile` raises `ER_UDF_ERROR` when an argument is empty;
  `probe_outer` does nothing with its arguments; `probe_counts()` reports the per-function init and
  deinit counts since `probe_reset()`.
- Build and load: `INSTALL COMPONENT 'file://component_probe';` (the URN form for a component
  installed from the plugin directory; `tests/probe/CMakeLists.txt` produces `component_probe.so`).
- **The simplest reproduction — no nesting, no parameter:**

  ```sql
  CREATE TABLE t (d VARCHAR(10), c VARCHAR(10));
  INSERT INTO t VALUES ('d1', 'c1');
  PREPARE s FROM 'SELECT probe_outer(d), c FROM t';
  EXECUTE s;                            -- ok
  ALTER TABLE t DROP COLUMN c;
  EXECUTE s;                            -- ERROR 1054: Unknown column 'c' in 'field list'
  SELECT probe_counts();                -- {"probe_outer":{"init":2,"deinit":1}, ...}
  UNINSTALL COMPONENT 'file://component_probe';
                                        -- ERROR 3538 ... De-initialization method provided by
                                        -- component 'probe' failed.
  ```

  `init` 2 against `deinit` 1 is the leak in one number; a restart clears it.

- **The shape it was found with** (nesting plus a bound parameter, the inner raising on the empty
  argument):

  ```sql
  SET @a = 'x'; SET @b = 'y';
  PREPARE s FROM 'SELECT probe_outer(probe_raise_volatile(?, ?), ?)';
  EXECUTE s USING @a, @b, @b;           -- ERROR 3200 ... no value for the argument
  EXECUTE s USING @a, @b, @b;           -- ERROR 3200 again
  DEALLOCATE PREPARE s;
  SELECT probe_counts();                -- {"probe_raise_volatile":{"init":2,"deinit":0}, ...}
  UNINSTALL COMPONENT 'file://component_probe';   -- ERROR 3538
  ```

The same shape with this project's own functions, which is how it was found in production code:

```sql
PREPARE s FROM 'SELECT gcm_decrypt(gcm_encrypt(?, ?), ?)';
EXECUTE s USING @k, @k, @k;   -- ERROR 3200 ... key must be 32, 24 or 16 bytes ...; got 0
UNINSTALL COMPONENT 'file://component_gcm';   -- ERROR 3538
```

## Severity

- **Availability, not just hygiene**: the component cannot be uninstalled or replaced without a
  server restart, and the leaked `UDF_INIT` and its buffers are never freed. A session that writes
  one of these shapes repeatedly accumulates them.
- **The dropped instance may hold secrets.** A `UDF_INIT` can legitimately hold a key read from the
  keyring (this project's key-id functions do, by design, for cross-row reuse) or a key copy and a
  scheduled context. Nothing wipes an instance the server drops without an error, and the component
  never regains control of it: that is a risk the component cannot eliminate from its side
  (`docs/design.md` amendment A16 states that limit rather than implying a guarantee).
- **It is not limited to a shape an application writes deliberately.** The `ALTER TABLE` case needs
  only a prepared statement over a table whose schema changes between executions. Sealing in one
  statement and opening in another — the normal use of a UDF — is unaffected, and so is nesting
  inside a builtin (`LENGTH(gcm_encrypt(?, ?))`).

## Suggested fix, for the server (not attempted here)

Whichever of the abort paths is taken, the deferred handler has to be given back:

- `Item_udf_func::fix_fields()`'s `if (thd->is_error()) return true;` and every `return true` out of
  `udf_handler::call_init_func()` after the guard was deferred should run the release the guard would
  have run, or
- `udf_handler::cleanup()`'s early return for `is_stmt_prepare() && is_repreparing` should be paired
  with a deferred release that runs if that prepare fails, rather than relying on an execution that
  will never happen.

Either way the fix belongs in `sql/item_func.cc`; a component cannot reach it.

## What this draft does not establish

- Whether `udf_handler::cleanup()` is **called** during the failed re-prepare and early-returns, or is
  never called for that item. The probe counts de-inits, not cleanup calls, and both produce the same
  leak; the distinction only matters for choosing between the two fixes above.
- Anything about memory beyond the leaked `UDF_INIT` and the use count — no heap analysis was done.
- Why the parameter is empty at that moment beyond "the evaluation happens inside the fix/re-prepare
  phase, before the values are bound" — that is the phase the probe and the call sites show; the
  parameter-binding order itself was not instrumented.
- Whether any release other than the three majors behaves differently. Only 8.0.43/8.0.46, 8.4.11 and
  9.4.0 were built and measured.
- No patch, no upstream issue number, and no reproduction on a MySQL build without this component:
  the probe is the minimal subject and it is in this repository.
