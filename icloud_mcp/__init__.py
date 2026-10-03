"""iCloud MCP — an MCP server for iCloud Mail, Calendar and Contacts.

Read-only by default. Send and destructive actions are gated. The app-specific
password lives only in the macOS Keychain (service "icloud-mcp"), never in a file.
"""

__version__ = "1.2.0"
