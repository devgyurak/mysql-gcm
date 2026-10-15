-- Collation differential for the n-gram token index (design amendment A17, question 4).
--
-- The invariant: the designated final filter must never miss a row the index should have
-- offered. If a token is computed on a normalisation the final LIKE does not use, the
-- index silently drops rows the decryption would have matched. This runs with PLAIN SQL
-- ONLY — no component function and no C++ — and is executed by scripts/leakage-collation.sh
-- on a throwaway 8.0 / 8.4 / 9.x server.
--
-- For every (h, q) where the final filter `h LIKE '%q%'` is true, the token computed from q
-- must be contained in the token set of h. Two candidate token normalisations are compared:
--   N1 utf8mb4_0900_bin   (binary, exact bytes)
--   N2 WEIGHT_STRING(...) (let MySQL normalise, per the collation)
-- A pair where the final filter matches but the tokenisation does not is a counterexample.
-- Nothing is blamed on the environment: the count and the pairs are printed as they are.
--
-- A second invariant is checked for the SQL side of the decision rather than the index:
-- the final filter's monotonicity under prefix extension. If q is a byte-substring of
-- q′ and `h LIKE '%q′%'`, then `h LIKE '%q%'` must hold — the guard the "refine inside
-- the previous result" recipe relies on (docs/like-recipes.md, recipe 4). A violation is
-- a case where refining a needle inside a previous result would silently drop a row.

DROP DATABASE IF EXISTS gcm_leakage;
CREATE DATABASE gcm_leakage CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE gcm_leakage;

-- The declared repertoire: Korean syllables and jamo, Latin-1 and extended Latin, a
-- ligature, full width, and case/accent/width variants of the same string. A query that is
-- not byte-identical to its haystack is the case where a normalisation can diverge.
CREATE TABLE repertoire (
    h VARCHAR(64) NOT NULL,
    q VARCHAR(64) NOT NULL,
    note VARCHAR(64) NOT NULL
) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;

INSERT INTO repertoire (h, q, note) VALUES
    ('홍길동',   '길',     'korean substring'),
    ('홍길동',   '홍',     'korean prefix'),
    ('김철수',   '철수',   'korean suffix'),
    ('한글날',   '글',     'korean middle'),
    ('CAFÉ',    'café',   'case and accent'),
    ('CAFÉ',    'CAFE',   'accent stripped'),
    ('Ångström','ANGSTR', 'case and accent'),
    ('Straße',  'STRASSE','eszett'),
    ('ﬁle',     'file',   'ligature'),
    ('ＡＢＣ',   'ABC',    'full width'),
    ('Müller',  'Ü',      'umlaut variant'),
    ('가나다',   '나',     'korean syllable'),
    ('가나다',   '나',     'decomposed jamo'),
    ('Seoul',   'SEOUL',  'ascii case'),
    ('Seoul',   'Seoul',  'exact'),
    -- Hangul IME composition states. A Korean input method moves through needles that are
    -- not extensions of one another (김 → 김ㄱ → 김기 → 김길), so the "refine inside the
    -- previous result" recipe (docs/like-recipes.md, recipe 4) must fall back to a fresh
    -- search between them. 김 is a byte-substring of 김ㄱ and 김기, but 김길동 contains
    -- neither, so these two rows record that the final filter returns 0 for the
    -- intermediate states; the extension the guard accepts is covered by 김 ⊂ 김길 above.
    ('김길동',   '김',     'ime prefix extension'),
    ('김길동',   '김길',   'ime extension'),
    ('김길동',   '김ㄱ',   'ime intermediate, 김길동 does not contain it'),
    ('김길동',   '김기',   'ime intermediate, 김길동 does not contain it');

CREATE TABLE numbers AS
WITH RECURSIVE seq AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM seq WHERE n < 20)
SELECT n FROM seq;

-- Every substring of every h, so the exact direction is covered too (final filter true,
-- exact token present).
CREATE TABLE derived AS
SELECT DISTINCT r.h AS h, SUBSTRING(r.h, a.n, b.n) AS q, 'derived' AS source
FROM repertoire r
JOIN numbers a ON a.n <= CHAR_LENGTH(r.h)
JOIN numbers b ON b.n <= CHAR_LENGTH(r.h) - a.n + 1
WHERE SUBSTRING(r.h, a.n, b.n) <> '';

CREATE TABLE results (
    h VARCHAR(64) NOT NULL,
    q VARCHAR(64) NOT NULL,
    source VARCHAR(16) NOT NULL,
    note VARCHAR(64) NULL,
    final_filter TINYINT NOT NULL,
    n1_binary TINYINT NOT NULL,
    n2_weight TINYINT NOT NULL
) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;

INSERT INTO results (h, q, source, note, final_filter, n1_binary, n2_weight)
SELECT h, q, 'repertoire', note,
       (h LIKE CONCAT('%', q, '%')),
       (h COLLATE utf8mb4_0900_bin LIKE CONCAT('%', q, '%') COLLATE utf8mb4_0900_bin),
       (LOCATE(WEIGHT_STRING(q), WEIGHT_STRING(h)) > 0)
FROM repertoire
UNION ALL
SELECT h, q, source, NULL,
       (h LIKE CONCAT('%', q, '%')),
       (h COLLATE utf8mb4_0900_bin LIKE CONCAT('%', q, '%') COLLATE utf8mb4_0900_bin),
       (LOCATE(WEIGHT_STRING(q), WEIGHT_STRING(h)) > 0)
FROM derived;

-- The index's actual invariant: if the final filter matches q in h, then EVERY n-gram of q
-- (orders 1 to 3) must be found in h under the token normalisation. The test is an EQUALITY of
-- weight strings at some position in h — a substring/`LOCATE` of one weight string inside another
-- could both miss a real hit and invent one across weight boundaries, so it is not the invariant.
CREATE TABLE gram_results AS
SELECT r.h AS h, r.q AS q, SUBSTRING(r.q, a.n, b.n) AS gram
FROM repertoire r
JOIN numbers a ON a.n <= CHAR_LENGTH(r.q)
JOIN numbers b ON b.n <= 3 AND a.n + b.n - 1 <= CHAR_LENGTH(r.q);

SELECT 'summary' AS section, 'N1 binary' AS normalisation, COUNT(*) AS counterexamples
FROM results WHERE final_filter = 1 AND n1_binary = 0
UNION ALL
SELECT 'summary', 'N2 weight', COUNT(*)
FROM results WHERE final_filter = 1 AND n2_weight = 0
UNION ALL
-- The IME intermediates the repertoire carries: they must NOT be matched, or the guard
-- of recipe 4 would accept a refinement between two states that are not extensions.
SELECT 'summary', 'IME intermediate hits', COUNT(*)
FROM results WHERE note LIKE 'ime intermediate%' AND final_filter = 1
UNION ALL
SELECT 'summary', 'N2 n-gram violations', COUNT(*)
FROM gram_results g
WHERE (g.h LIKE CONCAT('%', g.q, '%'))
  AND NOT EXISTS (
      SELECT 1 FROM numbers c
      WHERE c.n + CHAR_LENGTH(g.gram) - 1 <= CHAR_LENGTH(g.h)
        AND WEIGHT_STRING(SUBSTRING(g.h, c.n, CHAR_LENGTH(g.gram))) = WEIGHT_STRING(g.gram)
  );

SELECT 'counterexample' AS section, h, q, source, note
FROM results
WHERE final_filter = 1 AND (n1_binary = 0 OR n2_weight = 0)
ORDER BY source, h, q;

SELECT 'check' AS section,
       CASE WHEN COUNT(*) = 0 THEN 'N1 binary: no counterexample'
            ELSE CONCAT('N1 binary: ', COUNT(*), ' counterexample(s)') END AS outcome
FROM results WHERE final_filter = 1 AND n1_binary = 0
UNION ALL
SELECT 'check',
       CASE WHEN COUNT(*) = 0 THEN 'N2 weight: no counterexample'
            ELSE CONCAT('N2 weight: ', COUNT(*), ' counterexample(s)') END
FROM results WHERE final_filter = 1 AND n2_weight = 0;

-- Monotonicity under prefix extension. q is a byte-substring (utf8mb4_0900_bin) of q′,
-- and shorter: the guard the "refine inside the previous result" recipe uses to decide
-- that a new needle still contains the old one. The relation is byte-level so a
-- collation's case/accent/width folding cannot invent an extension the application
-- never typed; the implication itself is the final filter, in the table's own collation.
CREATE TABLE needle AS
SELECT q FROM repertoire UNION SELECT q FROM derived;

CREATE TABLE extensions AS
SELECT DISTINCT a.q AS q, b.q AS q_prime
FROM needle a JOIN needle b
  ON LOCATE(a.q COLLATE utf8mb4_0900_bin, b.q COLLATE utf8mb4_0900_bin) > 0
 AND CHAR_LENGTH(a.q) < CHAR_LENGTH(b.q);

CREATE TABLE computed_mono AS
SELECT hy.h AS h, x.q AS q, x.q_prime AS q_prime
FROM extensions x JOIN (SELECT DISTINCT h FROM repertoire) hy
WHERE (hy.h LIKE CONCAT('%', x.q_prime, '%'))
  AND NOT (hy.h LIKE CONCAT('%', x.q, '%'));

SELECT 'summary' AS section, 'Mono prefix-extension violations' AS normalisation,
       COUNT(*) AS counterexamples
FROM computed_mono;

-- The pairs themselves, so a non-zero count is diagnosable rather than a bare number.
SELECT 'mono counterexample' AS section, h, q, q_prime
FROM computed_mono ORDER BY h, q, q_prime;