"""The agent colours (the five colours of the web app) and the colours of the interface.

The interface uses the terminal's own text colour and its bold and dim
attributes for text, so it reads on dark and on light backgrounds. Colour
marks state: the agent's colour for the agent and the current step, green
for done, the severity colours for findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .term import RGB, Style

# The colours of AgentAvatar (light, base, dark), in the order of the colour picker.
AGENT_COLORS: dict[str, tuple[str, RGB, RGB, RGB]] = {
    "cobalt": ("Cobalt", (169, 181, 255), (80, 104, 244), (44, 63, 192)),
    "moss": ("Moss", (180, 224, 189), (94, 159, 111), (55, 111, 71)),
    "coral": ("Coral", (255, 198, 180), (236, 122, 93), (191, 79, 53)),
    "plum": ("Plum", (220, 198, 255), (155, 110, 226), (108, 68, 179)),
    "sand": ("Sand", (251, 230, 194), (224, 181, 120), (173, 129, 70)),
}
DEFAULT_AGENT_COLOR = "sand"
SEVERITY_ORDER = ("critical", "high", "medium", "low", "unknown")


def mix(a: RGB, b: RGB, t: float) -> RGB:
    return (round(a[0] + (b[0] - a[0]) * t), round(a[1] + (b[1] - a[1]) * t), round(a[2] + (b[2] - a[2]) * t))


@dataclass(frozen=True)
class Theme:
    color: str
    background: str
    accent: RGB
    accent_text: RGB
    ok: RGB
    warn: RGB
    error: RGB
    badges: dict[str, RGB] = field(default_factory=dict)

    @property
    def text(self) -> Style:
        return Style()

    @property
    def bold(self) -> Style:
        return Style(bold=True)

    @property
    def dim(self) -> Style:
        return Style(dim=True)

    @property
    def mark(self) -> Style:
        """The agent's colour, for symbols: the cursor, the active step, the progress bar."""
        return Style(fg=self.accent, bold=True)

    @property
    def name(self) -> Style:
        """The agent's name and other accented text."""
        return Style(fg=self.accent_text, bold=True)

    @property
    def good(self) -> Style:
        return Style(fg=self.ok, bold=True)

    @property
    def caution(self) -> Style:
        return Style(fg=self.warn, bold=True)

    @property
    def bad(self) -> Style:
        return Style(fg=self.error, bold=True)

    @property
    def tag(self) -> Style:
        """A small label on the agent's colour."""
        return Style(fg=(20, 20, 24), bg=self.accent, bold=True)

    def severity(self, name: str) -> Style:
        return Style(fg=(20, 20, 24), bg=self.badges.get(name, self.badges["unknown"]), bold=True)


def theme_for(color: str = DEFAULT_AGENT_COLOR, background: str = "dark") -> Theme:
    _, light, base, dark = AGENT_COLORS.get(color, AGENT_COLORS[DEFAULT_AGENT_COLOR])
    if background == "light":
        return Theme(
            color=color,
            background=background,
            accent=base,
            accent_text=dark,
            ok=(30, 135, 70),
            warn=(160, 110, 0),
            error=(190, 40, 40),
            badges={
                "critical": (230, 70, 70),
                "high": (240, 130, 80),
                "medium": (235, 185, 60),
                "low": (120, 160, 240),
                "unknown": (170, 170, 170),
            },
        )
    return Theme(
        color=color,
        background=background,
        accent=base,
        accent_text=mix(base, light, 0.45),
        ok=(139, 212, 156),
        warn=(242, 193, 78),
        error=(255, 107, 107),
        badges={
            "critical": (255, 95, 95),
            "high": (255, 138, 92),
            "medium": (242, 193, 78),
            "low": (143, 179, 255),
            "unknown": (170, 170, 170),
        },
    )
