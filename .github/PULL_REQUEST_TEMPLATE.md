## Summary

<!-- What does this change do, and why? -->

## Checklist

- [ ] `make lint` and `make test` pass.
- [ ] Tests cover the change.
- [ ] The change does not change a model request, a prompt, a policy or an engine parameter; or the description says so, and the golden fixtures (`make golden`) and `CHANGELOG.md` show it. Such a change leaves the benchmarked configuration and needs a new benchmark before it can be the default.
- [ ] No key, no customer code and no content of an agent session is in the change, in a test fixture or in a log.
- [ ] The documentation (`README.md`, `docs/`) and `CHANGELOG.md` are up to date.
