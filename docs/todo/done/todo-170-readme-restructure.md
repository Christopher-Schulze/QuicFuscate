# TODO-170: README.md Restructure

## Status
**DONE**

## Severity
**LOW**

## Context
`README.md` is approximately 30KB and lacks clear structure. Features, configuration, installation instructions, and architecture details are intermixed without a navigable hierarchy. Users cannot quickly find what they need.

- `README.md`: ~30KB, no table of contents, mixed content sections

## Root Cause
Content was accumulated incrementally without periodic restructuring. No information architecture was applied.

## Fix Plan
1. Audit current README.md content and categorize all sections
2. Define clear section hierarchy:
   - Quick Start (< 1 page to get running)
   - Installation (platform-specific)
   - Configuration (reference to config docs)
   - Architecture Overview (brief, link to docs/DOCUMENTATION.md)
   - Features (concise list with links to detailed docs)
   - Development (build, test, contribute - link to CONTRIBUTING.md)
   - License
3. Add table of contents with anchor links
4. Move detailed content to appropriate docs/ files
5. Keep README under 10KB with links to detailed documentation
6. Ensure quick-start guide works end-to-end

## Acceptance Criteria
- README.md under 10KB
- Table of contents with working anchor links
- Quick-start section enabling new users to run the project in < 5 minutes
- Detailed content moved to docs/ (not deleted)
- All links functional

## Dependencies
- TODO-171 (deployment guide) - some content may move there
- TODO-172 (troubleshooting guide) - some content may move there

## Affected Files
- `README.md`
- `docs/DOCUMENTATION.md` (may receive moved content)
