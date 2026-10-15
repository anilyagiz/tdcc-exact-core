# Oracle answer quality: decision rules and prompts

`docs/exact.md` section 8 found that LFM2.5-230M, with the job's prompt, answers Yes to all
seven test questions. The oracle computes the model faithfully, but the answer is not useful.
This note covers the tooling to measure better decision rules and prompts, what has been run
so far, and what the job must change for a calibrated rule to stay deterministic and
verifiable.

## Method

`tools/oracle_eval.py` scores the oracle on `tests/data/oracle_questions.jsonl`: 64 short
factual questions (32 Yes, 32 No) covering arithmetic, science, geography and history, with
answers that do not change over time.

For each question and each prompt format, it runs the fp32 reference on the prompt's token
ids: Hugging Face transformers in float32 by default, or openTPU's numpy reference with
`--ref numpy`. It records the margin `m = logit[Yes] - logit[No]` after the last prompt
token. The `job` format uses `tdcc_exact.oracle.new_job` itself, so its token ids are exactly
the ones a job carries.

| Format | Prompt |
|:--|:--|
| `job` | The chat template with the system line "Answer with exactly one word: Yes or No." and the question (today's job). |
| `nosys` | The chat template with the question as the only user turn. |
| `completion` | No chat template: `Question: <q>\nAnswer (Yes or No):`. The answer tokens are `" Yes"` and `" No"`, with a leading space. |
| `fewshot` | The job's system line, then two worked turns ("Is ice frozen water?" Yes; "Is the Moon larger than the Earth?" No), then the question. |

Every rule answers Yes if and only if `m - offset > 0`. A tie is No, as in `run_job`.

| Rule | Offset |
|:--|:--|
| `raw` | 0. This is today's rule. |
| `cf` | The margin on the content-free question "N/A" in the same format. It needs no labels. |
| `median` | The median margin over the training half. It needs no labels, only a sample of questions. |

The split into a training half and a test half is seeded (`--seed`, default 0) and stratified
by answer, so each half has 16 Yes and 16 No questions. Offsets come from the training half
only. Accuracies are reported on the test half. `raw` is also reported on all 64 questions.

The tool also reports the AUC: the fraction of (Yes question, No question) pairs in which the
Yes question has the larger margin. The AUC is the ceiling for any offset rule. If it is close
to 0.5, no threshold helps, because the margin carries no information about the answer. The
tool also prints the per-class margin distribution (mean, min, median, max).

`--json OUT` writes every question's margin. `--selftest` checks the split, the rules, the
metrics and the questions file on fake margins.

## What ran

**Not the model.** The session's network policy refused the downloads:

- `download.pytorch.org` gave 403 on CONNECT, so the CPU torch wheel could not be installed.
- `huggingface.co` gave 403 for both `hf download LiquidAI/LFM2.5-230M` and a direct `curl`
  of `config.json`.

PyPI was reachable. transformers 5.20.0 and huggingface_hub 2.2.0 installed in the scratch
virtual environment, but with no torch and no checkpoint there was nothing to run.

What did run:

- `python3 tools/oracle_eval.py --selftest` passes. The fake "always Yes, but ranked" margins
  give `raw` 54.5% (Yes 100%, No 0%) and `cf`/`median` 100%.
- An end-to-end run of `run()` and `table()` with a stub tokenizer and stub logits completed.
  This only checks the plumbing, so it gives no numbers about the model.

**There is no results table for LFM2.5-230M yet.** To produce one on a machine that can reach
Hugging Face:

    pip install torch --index-url https://download.pytorch.org/whl/cpu
    pip install transformers huggingface_hub safetensors jinja2
    hf download LiquidAI/LFM2.5-230M --local-dir models/LFM2.5-230M
    python3 tools/oracle_eval.py --model models/LFM2.5-230M --json oracle_eval.json
    python3 tools/oracle_eval.py --model models/LFM2.5-230M --ref numpy   # cross-check, no torch

### Evidence available now (from docs/exact.md section 8, not from this tool)

The seven fp32 margins already published for the `job` format are:

| Class | Margins |
|:--|:--|
| Yes | 6.10, 4.45, 4.21 |
| No | 5.83, 4.56, 5.36, 5.27 |

Only 4 of the 12 (Yes, No) pairs are ranked correctly, an AUC of 0.33. On these seven
questions, no offset makes the `job` format a useful oracle, because the margin does not rank
the classes at all. The same section reports that `nosys` got 7 of 10 right, with margins of
0.0 to 0.4 on three of the questions. That is the format most worth measuring first.

## Recommended rule

The rule should take this form:

    answer = Yes  iff  float32(logits[yes_id]) - float32(logits[no_id]) > offset

- `offset` is a constant fixed when the job is created. It is the training-half median margin
  for the chosen format, measured on Exact Core's int8 logits. The fp32 margins are not
  suitable: the device's logits differ from fp32 by up to about 0.5, which is the same size as
  the spread between the classes.
- Which format to use, and whether to use any offset rule at all, depends on the run above.
  Adopt the rule only if the test-half AUC is clearly above 0.5, say 0.75 or more. Otherwise
  the 230M model is the limit, and no rule fixes it.
- Prefer `median` over `cf`. `cf` needs a second prompt's logits. Unless that second run is
  also part of the job and committed in its trace, a verifier cannot check where the offset
  came from. A frozen constant avoids that.

## What must change in the job (tdcc_exact/oracle.py, not edited here)

1. **Put the rule in the job digest.** Add fields such as `rule: "margin_gt"` and `offset`
   (and the prompt format's name) to `Job`. `Job.digest` hashes `asdict(self)`, so they are
   covered automatically. The offset should be stored exactly, as an integer in fixed-point
   units or as a float32 bit pattern, and not as a decimal string that two parsers could round
   differently.
2. **Derive the answer from the committed logits.** `run_job` already computes the answer from
   the same `logits` array whose hash goes into the fingerprint (`lh = h(logits.tobytes())`).
   Keep it that way. Compute the comparison in float32 (`np.float32(lg[y]) - np.float32(lg[n])
   > np.float32(offset)`), so that every verifier, including one in a different language,
   gets the same bit-exact result. A verifier must recompute the answer from the revealed
   logits and the job's rule, and reject a receipt whose `answer` does not match.
3. **Record calibration provenance, but do not verify against it.** For audit, record the
   model hash, the questions file hash, the seed and the format the offset was learned from.
   Verification needs only the job's own fields.
4. **Keep the tie rule.** `m == offset` answers No, as `>` does today.

## Model license

The license could not be checked from the downloaded files, because the download was blocked,
so there is no `README.md` model card to read. From memory, which is not verified here,
LiquidAI's LFM2 models are published under the "LFM Open License v1.0" (`license: other`,
`license_name: lfm1.0`). That license is not Apache-2.0 and has a commercial-use revenue
threshold. Confirm this from the model card's front matter before shipping. TODO.md tracks
the same item.
