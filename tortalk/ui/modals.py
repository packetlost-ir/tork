from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Input, Static
from textual.containers import Container
from textual import events
from tork.config import normalize_and_validate_onion

class AddContactModal(ModalScreen[str | None]):
    """Command-palette-styled input for pasting a 56-char onion hash."""

    CSS = """
    AddContactModal {
        align: center top;
    }
    AddContactModal > #palette-box {
        width: 70%;
        max-width: 90;
        height: auto;
        margin-top: 3;
        border: thick $accent;
        background: $surface;
        padding: 0 0;
    }
    AddContactModal #onion-input {
        border: none;
        background: $surface;
        width: 100%;
        height: 3;
    }
    AddContactModal #hint-error {
        color: $error;
        background: $surface;
        width: 100%;
        height: auto;
        padding: 0 1;
        display: none;
    }
    AddContactModal #hint-error.visible {
        display: block;
    }
    """

    BINDINGS = [("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        with Container(id="palette-box"):
            yield Input(
                placeholder="Paste 56-character Onion ID and press Enter... (Esc to cancel)",
                id="onion-input",
            )
            yield Static("Invalid Onion ID: expected 56-character base32 hash.", id="hint-error")

    def on_mount(self) -> None:
        self.query_one("#onion-input", Input).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _show_error(self) -> None:
        err = self.query_one("#hint-error", Static)
        err.add_class("visible")
        inp = self.query_one("#onion-input", Input)
        inp.value = ""
        self.set_timer(0.4, lambda: err.remove_class("visible"))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        raw = event.value.strip()
        if not raw:
            self.dismiss(None)
            return
        is_valid, normalized, err = normalize_and_validate_onion(raw)
        if not is_valid or len(normalized.removesuffix(".onion")) != 56:
            self._show_error()
            return
        self.dismiss(normalized.removesuffix(".onion"))
