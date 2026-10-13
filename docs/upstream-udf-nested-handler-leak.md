# Upstream report draft — a nested loadable function leaks its `udf_handler` when the inner call raises

**Status: a draft. Not submitted anywhere.** It records what `mysql-gcm` found while building on the
loadable-function API (issue #43) so that the finding has one home in the repository. Sending it, in
whole or in part, is a separate, deliberate act for a human to take, and no text here may be pasted
into another tracker as if it were a filed report.

The finding is about **MySQL**, not about this component. The component cannot detect it, prevent it,
or work around it from inside; what it does instead is give up its own secrets on the error row
(`docs/design.md` amendment A16) so that a leaked instance retains nothing sensitive.

## Summary

When a loadable function is an argument of another loadable function and takes a prepared-statement
parameter, the outer function's `init` evaluates the inner call while the statement is being
re-prepared — before the parameter has a value — and the inner call then raises (it sees an empty
string where the parameter's value will be). The error aborts the fix/re-prepare phase, and the inner
`Item_udf_func`'s `udf_handler` is **never released** for the life of the server:

- its `UDF_INIT` is never passed to the function's de-initialisation function, and
- the `udf_func::usage_count` that `find_udf()` incremented is never given back.

The second one has a user-visible consequence: a component that registered those functions can no
longer be uninstalled (or upgraded in place) until the server restarts, because
`mysql_udf_registration::udf_unregister` succeeds only while `usage_count == 1`. The server reports
`ERROR 3538 (HY000): De-initialization method provided by component '<name>' failed.`

Reproduced on **8.0 (8.0.46), 8.4 (8.4.11) and 9 (9.4.0)**; the source read is against the 8.0.43,
8.4.11 and 9.4.0 trees, and the counts differ between 8.0 and the other two (below).

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

   `find_udf(name, len, /*mark_used=*/true)` does `udf->usage_count++`
   (`sql/sql_udf.cc`), and `free_handler()` → `free_udf()` does `--udf->usage_count`
   (`sql/sql_udf.cc`).

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

2. `sql/item_func.cc`, `udf_handler::call_init_func()` — this is where the inner call runs. A
   constant argument is evaluated during init:

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

   `get_string()` calls `args[index]->val_str(...)`. For an argument that is itself an
   `Item_udf_func`, that goes to `udf_handler::val_str()` → `get_arguments()` → the inner function's
   row callback, which is where it sees the parameter as empty and raises.

   **Version difference 1:** 8.0.43 does not have the `if (thd->is_error()) return true;` checks
   around the constant-argument evaluations; they were added later (8.4.11 and 9.4.0 have them).
   9.4.0 additionally requires `!args[i]->has_stored_program()`.

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

   That early return is correct when the re-prepare succeeds — the handler is about to be used by the
   execution. It is the problem when the re-prepare **fails**: no execution follows, so nothing
   revisits the handler, and the early return has already skipped the release.

4. `sql/item_func.cc`, `Item_udf_func::cleanup()` → `udf.cleanup()` is the only caller that reaches
   the release for a fixed item, and `~Item_udf_func() override = default;` in `sql/item_func.h`
   (same in all three trees) means destroying the item releases nothing. A statement that failed
   during fix/re-prepare discards the item tree without a cleanup pass, so the deferred handler is
   simply lost with the `MEM_ROOT`.

5. `sql/sql_udf.cc`, `mysql_udf_registration_imp::udf_unregister()` — the observable consequence:

   ```cpp
   if (!udf->dl && !udf->dlhandle &&  // Not registered via CREATE FUNCTION
       (udf->usage_count == 1))       // Not used
   ```

   A component-registered function sits at `usage_count == 1` when idle. One leaked handler leaves it
   at 2 or more, so unregister fails, and a component whose de-initialisation then refuses (as
   `mysql-gcm`'s does, to avoid freeing a live `UDF_INIT`) makes `UNINSTALL COMPONENT` fail with
   ER 3538.

## The sequence

1. `PREPARE s FROM 'SELECT outer(inner(?, ?), ?)'` — the first prepare fixes the inner item, and for
   it `is_in_prepare && !initid.const_item` may defer its `init`; either way the outer's item is
   marked fixed and the outer's handler is left deferred for execution.
2. `EXECUTE` re-prepares (`is_repreparing`). Cleanup runs first and early-returns (point 3), keeping
   both handlers.
3. Re-fixing the outer calls `udf_handler::fix_fields` for the inner as well, which takes a **second**
   use-count reference and calls the inner's `init` (`call_init_func`, because
   `is_in_prepare == false` while re-preparing).
4. The outer's own `call_init_func` then treats the inner as a constant argument and evaluates it
   (point 2) — the parameters do not have their values yet at this point.
5. The inner's row callback raises. In 8.4.11/9.4.0 `call_init_func` notices `thd->is_error()` and
   returns true **before** calling the outer's `init`; the outer's guard is still active and releases
   the outer's handler. The inner's handler was already deferred, so nothing releases it.
6. In 8.0.43 the missing check lets the outer's `init` run anyway; `udf_fun_guard` is then deferred
   and `Item_udf_func::fix_fields` aborts on its own `if (thd->is_error()) return true;` — so the
   outer's handler leaks too.
7. The item tree is discarded. No de-init function runs for the leaked handlers, and no use count is
   returned.

## The difference between the majors, measured

The repository's test-only probe component counts its own `init` and `deinit` calls
(`tests/probe/probe.cc`, run by `scripts/verify-nested.sh`). After `PREPARE` + two failing `EXECUTE`s
of `SELECT probe_outer(probe_raise_volatile(?, ?), ?)` (`probe_raise_volatile` raises on an empty
argument):

| MySQL | `probe_outer` init/deinit | `probe_raise_volatile` init/deinit | `UNINSTALL COMPONENT` |
|:--|:--|:--|:--|
| 8.0 (sources 8.0.43, server 8.0.46) | 2 / 0 | 2 / 0 | refused, ER 3538 |
| 8.4 (8.4.11) | 0 / 0 | 2 / 0 | refused, ER 3538 |
| 9 (9.4.0) | 0 / 0 | 2 / 0 | refused, ER 3538 |

`probe_outer` at 0 on 8.4/9 is step 5: the outer's `init` never ran, so there is nothing to de-init
for it. On 8.0 the outer's `init` ran twice (two `EXECUTE`s) and, per step 6, its handler leaked too.
The inner leaks on all three, which is why the uninstall is refused on all three. The controls in the
same sweep — the same nesting with literal arguments (nothing raises) and a bare bound parameter (no
nesting) — pair every init with its deinit, so the leak needs the raised error, not the nesting or the
parameter alone.

## Reproducer

Self-contained: one component with two functions and a counter, no keyring and no cryptography.

- Component: `tests/probe/probe.cc` in `mysql-gcm` (279 lines, uses only `udf_registration` and
  `mysql_runtime_error`). `probe_raise_volatile` raises `ER_UDF_ERROR` when any argument is empty;
  `probe_outer` does nothing with its arguments; `probe_counts()` reports the per-function init and
  deinit counts since `probe_reset()`.
- Build and load: `INSTALL COMPONENT 'file:///path/component_probe.so';`
- SQL:

  ```sql
  SET @a = 'x';
  SET @b = 'y';
  PREPARE s FROM 'SELECT probe_outer(probe_raise_volatile(?, ?), ?)';
  EXECUTE s USING @a, @b, @b;   -- ERROR 3200: ... UDF failed; no value for the argument
  EXECUTE s USING @a, @b, @b;   -- ERROR 3200 again
  DEALLOCATE PREPARE s;
  SELECT probe_counts();        -- {"probe_raise_volatile":{"init":2,"deinit":0}, ...}
  UNINSTALL COMPONENT 'file:///path/component_probe.so';
                                -- ERROR 3538 ... De-initialization method provided by
                                -- component 'probe' failed.
  ```

  `SELECT probe_counts()` after the statement is the direct evidence: two inits, no deinit. The
  refused `UNINSTALL COMPONENT` is the user-visible damage. A restart clears both.

The same shape with the component's own functions, which is how it was found:

```sql
PREPARE s FROM 'SELECT gcm_decrypt(gcm_encrypt(?, ?), ?)';
EXECUTE s USING @k, @k, @k;   -- ERROR 3200 ... key must be 32, 24 or 16 bytes ...; got 0
UNINSTALL COMPONENT 'file:///path/component_gcm.so';   -- ERROR 3538
```

## Severity, from this component's point of view

- **Availability, not confidentiality**: the component cannot be uninstalled or replaced without a
  server restart, and the leaked `UDF_INIT` and its buffers are never freed. A server whose sessions
  write this shape repeatedly accumulates them.
- A leaked `UDF_INIT` is component-owned memory that the component would otherwise have cleansed and
  released. For a function that keeps key material across rows, the leak is of key material; that is
  what amendment A16 addresses on the component's side, and it is why the error row now gives up
  every secret before it returns rather than waiting for a de-init that will not come.
- No SQL the application would normally write is affected: sealing and opening happen in separate
  statements. The shape needs a prepared-statement parameter passed into a loadable function that is
  itself an argument of another loadable function. The repository's operational constraint 18 tells
  users not to write it.
- Nesting inside a builtin (`LENGTH(gcm_encrypt(?, ?))`) is unaffected.

## Suggested fix, for the server (not attempted here)

Whichever of the two abort paths is taken, the deferred handler has to be given back:

- `Item_udf_func::fix_fields()`'s `if (thd->is_error()) return true;` (the 8.0 path) and every
  `return true` out of `udf_handler::call_init_func()` after the guard was deferred (the 8.4/9 path)
  should run the same release the guard would have run, or
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
