<!-- 
    Link Linear issues using magic words. Examples of these are "Closes RV-XXX", "Part of RV-YYY"
    or "Relates to RV-ZZZ".
-->

# What

<!--
    Summarise the changes in this MR.
-->

# Why

<!-- 
    Explain why this MR is needed.
-->

# How

<!--
    Explain how the MR achieves its goal. If this is trivial or if the code speaks for itself, you
    can omit this.
-->

# Manually Testing

```
make -C src/riscv all
```

# Regressions

<!--
    Explain changes to regression test captures. If there are no changes to these, delete this
    section.
-->

# Tasks for the Author

- [ ] Link all Linear issues related to this MR using magic words (e.g. part of, relates to, closes).
- [ ] Eliminate dead code and other spurious artefacts introduced in your changes.
- [ ] Document new public functions, methods and types.
- [ ] Make sure the documentation for updated functions, methods, and types is correct.
- [ ] Add tests for bugs that have been fixed.
- [ ] [Explain changes](#regressions) to regression test captures when applicable.
- [ ] Write commit messages to reflect the changes they're about.
- [ ] Self-review your changes to ensure they are high-quality.
- [ ] Complete all of the above before assigning this MR to reviewers.
