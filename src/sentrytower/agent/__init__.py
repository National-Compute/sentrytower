"""The single-agent engine of SentryTower: the Pi coding agent with read-only tools.

``runner.py`` runs one agent session with a token reserve, hard limits and at
most one final turn; ``session.py`` reads its session files; ``pi.py``
writes the agent configuration and builds its command; ``answer.py`` reads
the findings of its final answer.
"""
