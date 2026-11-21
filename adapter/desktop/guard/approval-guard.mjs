// Vanora Relay remote approval guard extension.
// Loaded explicitly via `--no-extensions -e <path>` when a desktop session or
// workspace configures approval_policy = "remote".
export default function (vanora) {
  const parsedTimeout = Number(process.env.VANORA_RELAY_APPROVAL_TIMEOUT_MS || "300000");
  const timeoutMs = Number.isFinite(parsedTimeout) && parsedTimeout > 0 ? Math.min(parsedTimeout, 300000) : 300000;

  vanora.on("tool_call", async (event, ctx) => {
    const tools = typeof vanora.getAllTools === "function" ? vanora.getAllTools() : [];
    const meta = Array.isArray(tools) ? tools.find((tool) => tool && tool.name === event.toolName) : undefined;
    const hints = meta?.annotations;
    const needsApproval =
      hints?.destructiveHint === true ||
      (!hints?.readOnlyHint && ((hints?.destructiveHint ?? true) || (hints?.openWorldHint ?? true)));
    if (!needsApproval) {
      return;
    }

    let preview = "";
    try {
      const serialized = JSON.stringify(event.input ?? event.args ?? {}, null, 2);
      if (serialized && serialized !== "{}") {
        preview = serialized.length > 2000 ? serialized.slice(0, 2000) + "\n...(truncated)" : serialized;
      }
    } catch {
      preview = "";
    }

    const title = `Allow tool "${event.toolName}"?`;
    const message = preview ? `${event.toolName}\n${preview}` : String(event.toolName || "tool");
    const confirmed = await ctx.ui.confirm(title, message, { timeout: timeoutMs });
    if (!confirmed) {
      return { block: true, reason: `${event.toolName} was not approved` };
    }
  });
}
