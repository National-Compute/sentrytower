"""The interactive terminal experience: the agent, the guided setup, the live audit view and the results.

Standard library only. Without a terminal (CI, a pipe, ``--plain``,
``NO_COLOR`` with ``TERM=dumb``) none of this runs: the command line prints
the plain progress lines of ``audit.Log``.

- ``term``: capabilities of the terminal and styled lines of text.
- ``theme``: the agent colours and the colours of the interface.
- ``mascot``: the agent as half-block pixel art.
- ``keys``, ``screen``, ``widgets``: key input, a live screen region and the prompts.
- ``catalog``, ``keychain``: model lists of an endpoint, and the key in the system keychain.
- ``setup``, ``live``, ``results``, ``home``: the screens.
"""
