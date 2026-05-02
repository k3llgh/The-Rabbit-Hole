**The Rabbit Hole**

_A collection of audit finding triage. Why things break under scrutiny._

This is where findings go when they don't survive adversarial trace analysis. Not patched. Not acknowledged. Just wrong — the mechanism doesn't work the way someone thought it did, or the math collapses at realistic scale, or every attempt at a fix opens a worse hole. Hours of tracing, building PoCs, and second-guessing yourself, all to arrive at "this isn't a vulnerability."
The goal is not to name protocols or auditors. It's to document what happens between the initial "this looks exploitable" and the final "never mind." The patterns repeat. Internal calls that someone treated like external calls. Rounding errors measured in atomic units. Reward formulas applied to zero balances. Fixes that would brick the protocol harder than the bug they're trying to patch. Duplicates dressed up with extra analysis that doesn't change the outcome.

Each entry strips a finding down to its essential logic, traces the mechanism step by step, and shows exactly where it falls apart. The code is representative, not production — enough to recognize the pattern without reproducing the implementation. Prior findings are referenced by their logic, not their source, so you can see when you're about to submit something that already exists.

Triage is a skill. It's the difference between a report that wastes everyone's time and one that actually improves security. This repository exists because that skill is rarely taught and almost never documented in public. Learn from our detours. If nothing else, you'll come out of it with a healthy distrust of your own first impressions.
