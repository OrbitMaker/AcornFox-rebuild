import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { request } from "node:http";

const socket = process.env.ACORNFOX_PI_TOOL_SOCKET ?? "";
const token = process.env.ACORNFOX_PI_RUN_TOKEN ?? "";
const ids = Type.String({ minLength: 1, maxLength: 128, pattern: "^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$" });
const applicationId = process.env.ACORNFOX_PI_APPLICATION_ID ?? "";
const appIdParameter = applicationId ? Type.Optional(ids) : ids;
const empty = Type.Object({});
const app = Type.Object({ application_id: appIdParameter });
const delivery = Type.Object({ application_id: appIdParameter, deployment_id: ids });
const tools: Array<[string, unknown]> = [
  ["acornfox_host_metrics", empty], ["acornfox_list_apps", empty], ["acornfox_app", app], ["acornfox_sources", app], ["acornfox_deliveries", app],
  ["acornfox_delivery_status", delivery], ["acornfox_logs", delivery], ["acornfox_operation_result", Type.Object({ application_id: appIdParameter, operation_id: ids })],
  ["acornfox_public_access", delivery], ["acornfox_probe", delivery],
  ["acornfox_propose_restart", delivery], ["acornfox_propose_redeploy", delivery],
];

function callback(tool: string, callId: string, arguments_: unknown, signal?: AbortSignal): Promise<unknown> {
  return new Promise((resolve) => {
    if (!socket || !token) return resolve({ ok: false, code: "unavailable" });
    let settled = false;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    let req: ReturnType<typeof request> | undefined;
    const abort = () => { finish({ ok: false, code: "unavailable" }); req?.destroy(); };
    const finish = (value: unknown) => {
      if (settled) return;
      settled = true;
      if (timeout) clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
      resolve(value);
    };
    if (signal?.aborted) return finish({ ok: false, code: "unavailable" });
    const body = JSON.stringify({ tool, call_id: callId, arguments: arguments_ });
    try {
      req = request({ socketPath: socket, path: "/tools", method: "POST", headers: {
        authorization: `Bearer ${token}`, "content-type": "application/json", "content-length": Buffer.byteLength(body),
      } }, (res) => {
        const chunks: Buffer[] = [];
        let bytes = 0;
        res.on("data", (chunk: Buffer) => {
          bytes += chunk.length;
          // Go permits a 64 KiB result; leave room for the response envelope.
          if (bytes > 66048) {
            finish({ ok: false, code: "result_too_large" });
            req?.destroy();
            return;
          }
          chunks.push(chunk);
        });
        res.on("error", () => finish({ ok: false, code: "unavailable" }));
        res.on("end", () => {
          try { finish(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
          catch { finish({ ok: false, code: "unavailable" }); }
        });
      });
      timeout = setTimeout(abort, 10000);
      req.on("error", () => finish({ ok: false, code: "unavailable" }));
      signal?.addEventListener("abort", abort, { once: true });
      req.end(body);
    } catch { finish({ ok: false, code: "unavailable" }); req?.destroy(); }
  });
}

const descriptions: Record<string,string>={acornfox_host_metrics:"Read current sampled host CPU, memory, root disk, and default-route network facts.",acornfox_list_apps:"List applications visible to this grant.",acornfox_app:"Read one application.",acornfox_sources:"List an application's source revisions.",acornfox_deliveries:"List an application's deliveries.",acornfox_delivery_status:"Read one delivery status.",acornfox_logs:"Read bounded delivery logs.",acornfox_operation_result:"Read an operation result for one application.",acornfox_public_access:"Read public-access state for one delivery.",acornfox_probe:"Actively request a safe, deployment-derived HTTP root probe."};
descriptions.acornfox_propose_restart = "Prepare a confirmation card to restart the exact deployment. This does not execute it; only the administrator can approve in the UI.";
descriptions.acornfox_propose_redeploy = "Prepare a confirmation card to recreate the exact deployment from its accepted source. This does not execute it; only the administrator can approve in the UI.";
export default function (pi: ExtensionAPI) {
  pi.on("before_agent_start", (event) => ({
    systemPrompt: event.systemPrompt + "\n\nYou are the AcornFox operations assistant. Respond in the user's language. Read current facts through the available tools and preserve unknown states. Accepted work is not verified work, and a single runtime or HTTP observation is not overall application health. Changes require a Go-issued confirmation card and administrator approval; never claim a prepared card has executed. " +
      (applicationId ? `This conversation is fixed to application ${applicationId}; application_id may be omitted in tools to use this application. Page navigation does not change this scope.` : "This conversation covers the local host. Use list_apps to find exact application identifiers."),
  }));
  for (const [name, parameters] of tools) pi.registerTool({ name, label: name, description: descriptions[name], parameters: parameters as never,
    async execute(toolCallId, params, signal) { const value = await callback(name, toolCallId, params, signal); return { content: [{ type: "text", text: JSON.stringify(value) }], details: {} }; },
  });
}
