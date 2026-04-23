"""Textual TUI for nmap with ML-powered command suggestions.

Layout:
  +------------------------+--------------------------+
  | Target:  [ 10.0.0.0/24 ]                          |
  | Command: [ nmap -sS -p- {target} ]                |
  | Describe what you want: [ ... ]                   |
  +------------------------+--------------------------+
  | Intent matches         | Next-flag suggestions    |
  | (TF-IDF model)         | (bigram model)           |
  +------------------------+--------------------------+
  | nmap output (live)                                |
  +---------------------------------------------------+

Keys:
  ctrl+r  run           ctrl+c  stop
  enter   (on a suggestion) accept it into the command
  tab     cycle focus
"""
from __future__ import annotations

import asyncio
from typing import ClassVar

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, Label, ListItem, ListView, RichLog

from .model import FlagHit, IntentHit, Suggester
from .runner import find_nmap, stream_nmap


class IntentList(ListView):
    """Vertical list of intent-match suggestions."""


class FlagList(ListView):
    """Vertical list of next-flag bigram suggestions."""


class TNmap(App):
    TITLE = "TNmap"
    CSS = """
    Screen { layout: vertical; }
    #inputs { height: auto; padding: 1 1 0 1; }
    #inputs Input { margin-bottom: 1; }
    #suggest { height: 30%; }
    #suggest > Vertical { width: 1fr; border: round $accent; padding: 0 1; }
    #suggest Label.title { color: $warning; text-style: bold; }
    #output { border: round $success; padding: 0 1; }
    ListView { height: 1fr; }
    ListItem { padding: 0 1; }
    ListItem:hover { background: $boost; }
    """

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("ctrl+r", "run_scan", "Run", priority=True),
        Binding("ctrl+x", "stop_scan", "Stop"),
        Binding("ctrl+t", "train_model", "Retrain"),
        Binding("ctrl+q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.suggester: Suggester = Suggester.load_or_train()
        self._task: asyncio.Task | None = None
        self._nl_debounce: asyncio.TimerHandle | None = None
        self._intent_seq: int = 0
        # Flip to True once the semantic encoder is warm. Until then intent
        # queries fall back to instant TF-IDF so the UI is usable from t=0.
        self._semantic_ready: bool = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Vertical(id="inputs"):
            yield Input(placeholder="Target (ip, host, or CIDR)", id="target", value="scanme.nmap.org")
            yield Input(placeholder="Command (edit freely, {target} placeholder supported)",
                        id="command", value="nmap -sV -sC {target}")
            yield Input(placeholder="Describe what you want in plain English", id="nl")
        with Horizontal(id="suggest"):
            with Vertical():
                yield Label("Intent matches (ML)", classes="title")
                yield IntentList(id="intent_list")
            with Vertical():
                yield Label("Next-flag suggestions (ML)", classes="title")
                yield FlagList(id="flag_list")
        yield RichLog(id="output", highlight=True, markup=True, wrap=True, auto_scroll=True)
        yield Footer()

    def on_mount(self) -> None:
        nmap = find_nmap()
        log = self.query_one("#output", RichLog)
        if nmap:
            log.write(f"[green]nmap located:[/] {nmap}")
        else:
            log.write("[red]nmap not found on PATH. Install from https://nmap.org/[/]")
        n_recipes = len(self.suggester.intent.recipes)
        sem = "semantic + reranker" if self.suggester.semantic is not None else "TF-IDF only"
        log.write(f"[cyan]Model loaded[/] - {n_recipes} recipes, "
                  f"{len(self.suggester.flags.vocab)} flag tokens, retriever: {sem}")
        self._refresh_flag_suggestions()
        if self.suggester.semantic is not None:
            log.write("[dim]warming semantic encoder...[/]")
            self._warmup_semantic()

    @work(thread=True, exclusive=True, group="warmup")
    def _warmup_semantic(self) -> None:
        """Load encoder off the UI thread. While loading, intent queries use
        the instant TF-IDF path; once done we flip to semantic."""
        import time
        log = self.query_one("#output", RichLog)
        self.call_from_thread(
            log.write, "[dim]loading semantic encoder in background (~15-20s)... "
            "TF-IDF is serving suggestions meanwhile[/]",
        )
        try:
            t0 = time.perf_counter()
            self.suggester.semantic.warmup_encoder()
            dt = time.perf_counter() - t0
            self._semantic_ready = True
            self.call_from_thread(
                log.write,
                f"[green]semantic encoder ready[/] ({dt:.1f}s) - "
                "suggestions now use dense retrieval + rerank",
            )
            # refresh current suggestions with the now-ready semantic model
            self.call_from_thread(self._rerun_current_intent)
        except Exception as exc:
            self.call_from_thread(
                log.write, f"[yellow]semantic encoder failed, staying on TF-IDF: {exc!r}[/]",
            )

    def _rerun_current_intent(self) -> None:
        value = self.query_one("#nl", Input).value
        if value.strip():
            self._intent_seq += 1
            self._intent_worker(value, self._intent_seq)

    def _intent_lookup(self, value: str, k: int = 8) -> list[IntentHit]:
        """Use semantic if warm, otherwise TF-IDF (always instant)."""
        if self._semantic_ready and self.suggester.semantic is not None:
            return self.suggester.suggest_intent(value, k=k)
        return self.suggester.intent.suggest(value, k=k)

    # --- input handling ---

    @on(Input.Changed, "#nl")
    def _on_nl_changed(self, event: Input.Changed) -> None:
        # Debounce: each keystroke resets a 250ms timer; the worker only
        # fires once the user has stopped typing. Uses a monotonically
        # increasing sequence so late workers can detect they're stale.
        self._intent_seq += 1
        seq = self._intent_seq
        value = event.value
        loop = asyncio.get_running_loop()
        if self._nl_debounce is not None:
            self._nl_debounce.cancel()
        # Shorter debounce when TF-IDF is active (instant), longer once
        # semantic + reranker is in use (~30-300ms).
        delay = 0.25 if self._semantic_ready else 0.05
        self._nl_debounce = loop.call_later(delay, self._run_intent_worker, value, seq)

    def _run_intent_worker(self, value: str, seq: int) -> None:
        self._intent_worker(value, seq)

    @work(thread=True, exclusive=True, group="intent")
    def _intent_worker(self, value: str, seq: int) -> None:
        if seq != self._intent_seq:
            return
        try:
            hits = self._intent_lookup(value, k=8)
        except Exception as exc:
            self.call_from_thread(
                self.query_one("#output", RichLog).write,
                f"[red]intent error:[/] {exc!r}",
            )
            return
        if seq != self._intent_seq:
            return  # newer keystroke already queued
        self.call_from_thread(self._apply_intent_hits, hits)

    def _apply_intent_hits(self, hits: list[IntentHit]) -> None:
        lv = self.query_one("#intent_list", IntentList)
        lv.clear()
        for h in hits:
            lv.append(ListItem(
                Label(f"{h.score:.2f}  {h.recipe.command}\n        [dim]{h.recipe.description}[/]"),
                name=h.recipe.command,
            ))

    @on(Input.Changed, "#command")
    def _on_command_changed(self, _: Input.Changed) -> None:
        self._refresh_flag_suggestions()

    def _refresh_flag_suggestions(self) -> None:
        cmd = self.query_one("#command", Input).value
        tokens, prefix = self._tokenize_for_suggest(cmd)
        hits = self.suggester.flags.suggest(tokens, k=10, prefix=prefix)
        lv = self.query_one("#flag_list", FlagList)
        lv.clear()
        for h in hits:
            lv.append(ListItem(Label(f"{h.prob:.3f}  {h.token}"), name=h.token))

    @staticmethod
    def _tokenize_for_suggest(cmd: str) -> tuple[list[str], str]:
        """Split the command for bigram lookup.

        Returns (context_tokens, active_prefix).
        Rules:
          - trailing whitespace -> user wants the NEXT token (no prefix)
          - trailing {target}   -> same; treat the token before it as context
          - otherwise the last chunk is a prefix being typed
        """
        parts = cmd.split()
        cleaned = [p for p in parts if p not in ("nmap", "{target}")]
        trailing_target = bool(parts) and parts[-1] == "{target}"
        if cmd.endswith(" ") or trailing_target:
            return cleaned, ""
        if cleaned:
            return cleaned[:-1], cleaned[-1]
        return [], ""

    # --- suggestion acceptance ---

    @on(ListView.Selected, "#intent_list")
    def _accept_intent(self, event: ListView.Selected) -> None:
        cmd = event.item.name if event.item else None
        if cmd:
            self.query_one("#command", Input).value = cmd
            self._refresh_flag_suggestions()

    @on(ListView.Selected, "#flag_list")
    def _accept_flag(self, event: ListView.Selected) -> None:
        token = event.item.name if event.item else None
        if not token:
            return
        cmd_input = self.query_one("#command", Input)
        cmd = cmd_input.value
        tokens, prefix = self._tokenize_for_suggest(cmd)
        if prefix:
            # replace the in-progress prefix
            idx = cmd.rfind(prefix)
            cmd = cmd[:idx] + token + " "
        else:
            if not cmd.endswith(" "):
                cmd += " "
            cmd += token + " "
        if "{target}" not in cmd:
            cmd = cmd.rstrip() + " {target}"
        cmd_input.value = cmd
        self._refresh_flag_suggestions()

    # --- actions ---

    def action_run_scan(self) -> None:
        target = self.query_one("#target", Input).value.strip()
        template = self.query_one("#command", Input).value.strip()
        log = self.query_one("#output", RichLog)
        if not target:
            log.write("[red]Target is empty.[/]")
            return
        if self._task and not self._task.done():
            log.write("[yellow]A scan is already running. Ctrl+X to stop it first.[/]")
            return
        log.write(f"\n[bold cyan]>>>[/] {template}  [dim](target={target})[/]")
        self._task = asyncio.create_task(self._run(template, target))

    async def _run(self, template: str, target: str) -> None:
        log = self.query_one("#output", RichLog)
        try:
            async for line in stream_nmap(template, target):
                log.write(line)
        except FileNotFoundError as exc:
            log.write(f"[red]{exc}[/]")
        except asyncio.CancelledError:
            log.write("[yellow][cancelled][/]")
            raise
        except Exception as exc:  # surface everything; operator tool, not library
            log.write(f"[red]error:[/] {exc!r}")

    def action_stop_scan(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()

    @work(thread=True)
    def action_train_model(self) -> None:
        self.suggester = Suggester.train()
        self.suggester.save()
        self.call_from_thread(
            self.query_one("#output", RichLog).write,
            "[green]Model retrained and cached.[/]",
        )
        self.call_from_thread(self._refresh_flag_suggestions)


def run() -> None:
    TNmap().run()


if __name__ == "__main__":
    run()
