/**
 * The one convention that lets a line opt out of a documentation gate.
 *
 * Two gates read the prose: `check-language` checks the spelling, `check-docs` checks the numbers.
 * Both have the same problem - a document that explains a rule has to be able to quote a violation
 * of it, and the conformance table lists the mutations that prove each gate fails, which means
 * spelling an Americanism and quoting a wrong count on purpose.
 *
 * So the escape is shared, spelled the same way in both gates, and documented in one place:
 *
 *     ... (gate-check: allow)
 *
 * It is deliberately verbose, so that it cannot appear by accident, and deliberately rare: two
 * documents use it today, both of them the ones that have to quote their own failures.
 *
 * @module gate-exemptions
 */

/** A line containing this is left alone by every documentation gate. */
export const GATE_OPT_OUT = /gate-check:\s*allow/;
