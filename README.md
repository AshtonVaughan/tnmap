# TNmap

A terminal UI for `nmap` with machine-learning powered command suggestions.

Type what you want in plain English - "find login pages", "check heartbleed", "enumerate smb shares on this box" - and TNmap surfaces the matching `nmap` invocation. It also predicts the next flag as you edit the command line. Hit Ctrl+R to run the scan, output streams live.

![TNmap screenshot placeholder](docs/screenshot.png)

## Why

The hard part of `nmap` is not running it, it's remembering which of the 600+ NSE scripts and 150+ flags maps to the thing you actually want to do. Cheat sheets are static; man pages are enormous; tab-completion only helps if you already know the first few characters.

TNmap solves this by training a retrieval model on:

- **613 NSE scripts** auto-harvested from your local Nmap installation (script name, description, categories, port hints all extracted from `.nse` source)
- **150+ flag definitions** sourced from the official man page
- **250+ real-world query -> command pairs** (126 hand-curated + ~130 scraped from HackTricks / StationX cheat sheets)

You get semantic retrieval with cross-encoder reranking out of the box. No API keys, no cloud round-trips, everything runs locally.

## Features

- **Natural language -> command** via sentence-transformer embeddings + cross-encoder rerank
- **Next-flag autocomplete** via a Markov bigram over real nmap command sequences
- **Graceful degradation**: TF-IDF serves suggestions instantly while the semantic encoder warms in the background, then it flips to dense retrieval transparently
- **Live output**: `nmap` runs as an async subprocess, every line streams into the output pane, `Ctrl+X` cancels a scan mid-flight
- **Debounced input**: suggestions update ~250 ms after you stop typing, no keypress jank
- **Retrain on demand**: `Ctrl+T` rebuilds the model from your current corpus + any new NSE scripts you install

## Install

Requires Python 3.10+, `nmap` installed, and ~200 MB free for the ML models.

```bash
git clone https://github.com/AshtonVaughan/tnmap.git
cd tnmap
pip install -r requirements.txt
python -m tnmap
```

First run will download two sentence-transformer models (~180 MB total) from HuggingFace into `~/.cache/huggingface/`. Subsequent runs use the local cache.

The trained model is cached at `tnmap/model.pkl` after first launch; retraining takes ~15 s.

## Usage

| Key | Action |
|---|---|
| `Ctrl+R` | Run the current command |
| `Ctrl+X` | Stop the running scan |
| `Ctrl+T` | Retrain the model |
| `Ctrl+Q` | Quit |
| `Tab` | Cycle focus between inputs |
| `Enter` | Accept the highlighted suggestion into the command line |

The UI has three input fields:

1. **Target** — IP, hostname, or CIDR. `scanme.nmap.org` by default (the official Nmap project test host).
2. **Command** — editable nmap command template. `{target}` is substituted at run time.
3. **Describe what you want** — free-form English. Suggestions populate below.

### Example queries

| Type this | Get |
|---|---|
| `find login pages` | `nmap -p 80,443,8080,8443 --script http-auth-finder {target}` |
| `check heartbleed` | `nmap -p 443 --script ssl-heartbleed {target}` |
| `detect eternalblue` | `nmap -p 445 --script smb-vuln-ms17-010 {target}` |
| `is the box vulnerable to any old smb exploits` | `smb-vuln-ms17-010`, `smb-vuln-ms10-054`, `cve-2017-7494` |
| `enumerate shares on windows` | `nmap -p 139,445 --script smb-enum-shares {target}` |
| `which users exist on the domain controller` | `krb5-enum-users`, `smb-enum-users` |
| `run the full pentesting toolkit at it` | `nmap -sS -sV -sC -p- -T4 -oA full {target}` |

## Architecture

```
User query (NL)
     |
     v
Sentence-Transformer (all-MiniLM-L6-v2) --> 384-dim embedding
     |
     v
Cosine similarity vs 3,596 recipe embeddings --> top-30 candidates
     |
     v
Cross-Encoder (ms-marco-MiniLM-L-6-v2) reranks top-30
     |
     v
Blended score (0.7 * reranker + 0.3 * retriever)
     |
     v
Dedupe by command, return top-k
```

For command editing (next-flag prediction):

```
Current tokens on the command line
     |
     v
Markov bigram over flag sequences (trained on corpus)
     |
     v
Laplace-smoothed probabilities, filtered by prefix
     |
     v
Top-k flag suggestions, live updated
```

### Training data pipeline

`tnmap/corpus.py:build_corpus()` fuses four sources:

1. **Real Q&A pairs** (`data_sources.EMBEDDED_PAIRS`, hand-curated from operator practice)
2. **Scraped cheat sheets** (`data_sources.scrape_all()` - best-effort HTTP fetch, cached under `tnmap/data_cache/`)
3. **NSE scripts** (`nse_scraper.load_all()` - parses every `.nse` file on disk for `description`, `categories`, `@usage`, infers ports from name prefix)
4. **Man-page flags** (`flags.FLAGS` - every documented nmap option)

Each entry gets 2-4 synthetic paraphrases for TF-IDF recall. The semantic model doesn't need paraphrases; descriptions go in raw.

## Project layout

```
tnmap/
  __main__.py         entry point
  app.py              Textual UI, worker threads, keybindings
  model.py            Suggester orchestrator (TF-IDF + semantic + bigram)
  semantic.py         sentence-transformer + cross-encoder retrieval
  corpus.py           training-corpus builder + paraphrase generator
  data_sources.py     embedded Q&A pairs + cheat-sheet scraper
  nse_scraper.py      parses local .nse files for metadata
  flags.py            nmap flag catalogue from the man page
  runner.py           async nmap subprocess streamer
```

## Configuration

No config file. Edit the corpora directly:

- New real-world pairs: append to `tnmap/data_sources.py::EMBEDDED_PAIRS`
- New flags: append to `tnmap/flags.py::FLAGS`
- New scraper sources: append URLs to `tnmap/data_sources.py::SOURCES`

Hit `Ctrl+T` in the UI or run `python -m tnmap.model` to retrain.

## Limitations

- Top-1 accuracy is ~85% on natural English; top-3 is near 100%. Ambiguous queries ("scan stuff") will give reasonable but not always right answers.
- The cross-encoder adds ~200 ms per query on CPU. Fast enough to feel instant after the 250 ms debounce, but noticeable on low-end hardware.
- Windows paths are hard-coded to `C:\Program Files (x86)\Nmap\nmap.exe` fallbacks. PATH lookup is tried first so most installs work.
- The scraper is best-effort. If HackTricks is unreachable, embedded pairs still ship.

## Scope and ethics

This tool runs `nmap`. Only run it against targets you have written authorization to test:

- Your own infrastructure
- `scanme.nmap.org` (explicitly authorised by the Nmap project)
- Bug bounty programs whose scope covers network scanning
- CTF infrastructure

Port scanning non-authorized hosts is, depending on jurisdiction, anywhere from a civil violation to a federal crime. Don't.

## License

MIT. See `LICENSE`.

## Acknowledgements

- [Nmap](https://nmap.org/) — the tool this wraps
- [Textual](https://textual.textualize.io/) — Python TUI framework
- [sentence-transformers](https://www.sbert.net/) — encoder + cross-encoder models
- [HackTricks](https://book.hacktricks.xyz/) and [StationX](https://www.stationx.net/) — cheat-sheet sources
