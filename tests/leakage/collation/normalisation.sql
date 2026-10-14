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
    ('Seoul',   'Seoul',  'exact');

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

SELECT 'summary' AS section, 'N1 binary' AS normalisation, COUNT(*) AS counterexamples
FROM results WHERE final_filter = 1 AND n1_binary = 0
UNION ALL
SELECT 'summary', 'N2 weight', COUNT(*)
FROM results WHERE final_filter = 1 AND n2_weight = 0;

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