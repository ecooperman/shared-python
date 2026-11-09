"""Code the personal apps (lists, trip-planning, ...) share instead of each keeping a copy.

  settings    the settings every app reads from the shared environment file
  auth        who is signed in: verifying Cloudflare Access's signed token
  cloudflare  letting an email through the Access login gate (the Invitees group)
  notify      telling the administrator something needs them, and emailing people

What differs between apps (admin emails, the app's name, the links in emails) is passed
in by the caller; what is the same everywhere lives here. See README.md.
"""
