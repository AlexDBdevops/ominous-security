# Labeled set

Measures every change to the rules or to `lib/review.js` with two questions: is there noise left?
And is the malicious stuff still detected?

- `test/helpers/malware.js`: malicious test repos (real techniques and attempts to slip through
  the severity downgrades). There is no real malware: everything points at `evil.example` and
  nothing runs. `npm test` checks them with and without the JavaScript parser.
- `labels.json`: findings from real repos reviewed by hand. A `real` label must come out at least
  at `min` (and at most `max`, if set); a `ruido` (noise) label cannot go above `max`. `rule` and
  `file` are regular expressions; `why` explains the decision.
- `score.js`: scores a batch (`npm run gold -- <folder with the JSON files>`) and lists at the end
  the medium-or-higher threats that have no label yet.

## When a false positive shows up

1. Label it in `labels.json` with the reason.
2. If the fix lowers something, add to `test/helpers/malware.js` the sample that would try to slip
   through that downgrade (it must still come out high).
3. `npm test`, then a batch with `npm run gold`.
