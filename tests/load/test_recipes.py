"""Regression checks for the recipe study harness's plan reading and SQL building."""

import unittest

import recipes
from run import FIXTURE_KEY_HEX


def context() -> recipes.Context:
    return recipes.Context(needle="김", dept=0, chunk=20000, limit=50, cursor=300001)


COVERING_PLAN = (
    "-> Limit: 50 row(s)  (cost=0.35 rows=1) (actual time=0.302..0.303 rows=2 loops=1)\n"
    "    -> Filter: (gcm_decrypt(patients.name_enc AS name_enc,<cache>((@k)))"
    " like '%길%')  (cost=0.35 rows=1) (actual time=0.256..0.257 rows=2 loops=1)\n"
    "        -> Covering index lookup on patients using ix_scope_id_enc (dept_id=1)"
    " (reverse)  (cost=0.35 rows=1) (actual time=0.0616..0.0829 rows=3 loops=1)\n"
)

# A filter with a preceding conjunct: the child's rows are the rows into the filter, not
# the rows decrypted, because `dept_id = 1` short-circuits the UDF for the other scopes.
SCOPE_PLAN = (
    "-> Limit: 50 row(s)  (cost=0.26 rows=50) (actual time=0.026..0.764 rows=50 loops=1)\n"
    "    -> Filter: ((patients.dept_id = 1) and (gcm_decrypt(patients.name_enc"
    " AS name_enc,<cache>((@k))) like '%김%'))  (actual time=0.022..0.758 rows=50 loops=1)\n"
    "        -> Index scan on patients using PRIMARY (reverse)"
    "  (actual time=0.009..0.549 rows=5530 loops=1)\n"
)

ICP_PLAN = (
    "-> Index lookup on patients using ix_scope_enc (dept_id=1), with index condition:"
    " (gcm_decrypt(patients.name_enc AS name_enc,<cache>((@k))) like '%길%')"
    "  (cost=0.35 rows=1) (actual time=0.0316..0.0325 rows=2 loops=1)\n"
)


class RowsIntoFilter(unittest.TestCase):
    def test_given_a_covering_plan_when_parsed_then_the_filter_child_is_the_rows(self) -> None:
        # Given: a Filter node whose child is a covering index lookup.
        plan = COVERING_PLAN
        # When
        rows, node, child = recipes.rows_into_filter(plan)
        # Then: the child's actual rows, with both node lines kept.
        self.assertEqual(rows, 3)
        self.assertIn("Filter:", node)
        self.assertIn("Covering index lookup", child)

    def test_given_a_preceding_conjunct_when_parsed_then_the_node_line_shows_it(self) -> None:
        # Given: a scope predicate before the UDF in the filter.
        plan = SCOPE_PLAN
        # When
        rows, node, _ = recipes.rows_into_filter(plan)
        # Then: 5,530 rows reached the filter, but the node line records the conjunct that
        #       means far fewer were decrypted — the number is read with the node.
        self.assertEqual(rows, 5530)
        self.assertIn("dept_id = 1", node)

    def test_given_an_icp_plan_when_parsed_then_there_is_no_child_and_no_count(self) -> None:
        # Given: index condition pushdown, so the condition sits inside the index read
        #        and there is no Filter node at all.
        plan = ICP_PLAN
        # When
        rows, node, child = recipes.rows_into_filter(plan)
        # Then: absent, not zero — the plan cannot say how many rows were decrypted.
        self.assertIsNone(rows)
        self.assertEqual((node, child), ("", ""))

    def test_given_a_plan_without_the_filter_when_parsed_then_absent(self) -> None:
        # Given: a plan that never mentions the decrypting function.
        plan = "-> Table scan on patients  (cost=1 rows=1) (actual time=0.1..0.1 rows=1 loops=1)\n"
        # When
        rows, node, child = recipes.rows_into_filter(plan)
        # Then
        self.assertIsNone(rows)
        self.assertEqual((node, child), ("", ""))


class PadValue(unittest.TestCase):
    def test_given_a_width_below_the_minimum_when_padded_then_it_is_eight_bytes(self) -> None:
        # Given: widths where the eight-digit scope id would overflow the column.
        # When / Then: the value stays the eight-digit id rather than being truncated.
        self.assertEqual(recipes.pad_value(3, 0), "00000003")
        self.assertEqual(recipes.pad_value(3, 1), "00000003")
        self.assertEqual(recipes.pad_value(3, 7), "00000003")

    def test_given_a_width_at_or_above_the_minimum_when_padded_then_it_is_that_wide(self) -> None:
        # Given: the widths the study runs use.
        # When / Then
        self.assertEqual(len(recipes.pad_value(3, 8)), 8)
        self.assertEqual(len(recipes.pad_value(3, 1024)), 1024)

    def test_given_a_scope_when_padded_then_the_id_is_zero_padded_to_eight_digits(self) -> None:
        # Given: a two-digit scope id.
        # When / Then
        self.assertEqual(recipes.pad_value(12, 16), "00000012" + "0" * 8)


class WindowBounds(unittest.TestCase):
    def test_given_a_cursor_when_window_is_computed_then_it_is_the_chunk_below(self) -> None:
        # Given: the first page of a 300,000-row table with a 20,000-row window.
        # When
        lower, upper = recipes.window_bounds(300001, 20000)
        # Then: (280001, 300001), the range the keyset page scans.
        self.assertEqual((lower, upper), (280001, 300001))

    def test_given_a_cursor_below_the_chunk_when_computed_then_lower_bound_is_zero(self) -> None:
        # Given: a cursor inside the first chunk.
        # When
        lower, upper = recipes.window_bounds(150, 20000)
        # Then: the lower bound does not go negative.
        self.assertEqual((lower, upper), (0, 150))


class RecipeSql(unittest.TestCase):
    def test_given_a_context_when_scope_built_then_dept_and_count_bound(self) -> None:
        # Given: a scoped search over the fixture.
        ctx = context()
        # When
        (statement,) = recipes.recipe_scope(ctx)
        # Then: the scope predicate binds first and the recipe aggregates.
        self.assertIn("WHERE dept_id = %s", statement.sql)
        self.assertEqual(statement.args, (0, FIXTURE_KEY_HEX, "%김%"))
        self.assertTrue(statement.aggregate)

    def test_given_a_context_when_scope_page_built_then_ordered_and_limited(self) -> None:
        # Given: a 50-row page inside a scope.
        ctx = context()
        # When
        (statement,) = recipes.recipe_scope_page(ctx)
        # Then: newest-first, bounded by the limit — the shape recipe 2 turns on.
        self.assertIn("ORDER BY id DESC LIMIT %s", statement.sql)
        self.assertEqual(statement.args, (0, FIXTURE_KEY_HEX, "%김%", 50))

    def test_given_a_cursor_when_window_built_then_clamped_bounds_bound(self) -> None:
        # Given: a cursor inside the first chunk, where the lower bound would go negative.
        ctx = context()
        ctx.cursor = 150
        # When
        (statement,) = recipes.recipe_window(ctx)
        # Then: the lower bound is clamped to 0, not passed through as -19850.
        self.assertEqual(statement.args[:2], (150, 0))

    def test_given_a_context_when_wide_read_built_then_pad_selected(self) -> None:
        # Given: the single-step recipe 2 read.
        ctx = context()
        # When
        (statement,) = recipes.recipe_wide_read(ctx)
        # Then: the non-indexed `pad` is selected, which is what ICP must avoid reading.
        self.assertIn("SELECT id, pad", statement.sql)
        self.assertEqual(statement.args, (0, FIXTURE_KEY_HEX, "%김%"))


class MatchCounting(unittest.TestCase):
    def test_given_an_aggregate_recipe_when_counted_then_the_value_is_the_result(self) -> None:
        # Given: a COUNT(*) recipe whose single value is the match count.
        statements = recipes.recipe_scan(context())
        # When
        matches = recipes.matches_of(statements, 29918)
        # Then
        self.assertEqual(matches, 29918)

    def test_given_a_row_recipe_when_counted_then_the_length_is_the_result(self) -> None:
        # Given: a recipe that returns the matched rows.
        statements = recipes.recipe_newest_first(context())
        # When
        matches = recipes.matches_of(statements, [(1,), (2,), (3,)])
        # Then
        self.assertEqual(matches, 3)


if __name__ == "__main__":
    unittest.main()
