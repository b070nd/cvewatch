package mcpserver

import "github.com/modelcontextprotocol/go-sdk/mcp"

func hints(readOnly, destructive, idempotent, openWorld bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{ReadOnlyHint: readOnly, DestructiveHint: &destructive, IdempotentHint: idempotent, OpenWorldHint: &openWorld}
}

func readHints() *mcp.ToolAnnotations { return hints(true, false, true, false) }

func writeHints(idempotent bool) *mcp.ToolAnnotations { return hints(false, false, idempotent, false) }
