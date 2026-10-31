"""The funnel engine of SentryTower: the engine of the hybrid for repositories of up to 1,000 files.

The orchestrator (``orchestrator.py``) selects the code to read, divides the
token budget and decides when to stop: a deterministic inventory, a model
rating of unit cards, one unit check for each unit, a blind triage of each
lead, deep-check agent sessions, a free-roaming agent session, line
resolution, blind verification and ranking, and the output caps. The
modules use the Python standard library only.
"""
