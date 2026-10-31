/**
 * Numbered read output for the agent of SentryTower.
 *
 * Pi's read tool returns the file text without line numbers. This tool_result
 * hook puts the line number in front of each line of a text read result:
 * `${String(n).padStart(5)}│${text}`. The hook changes only the text of the
 * result. The tool name, the schema, the description, the system prompt and
 * the lines that a read returns (offset, limit and truncation) stay the same.
 *
 * The hook keeps these results unchanged: an error, a result that is not one
 * text block (an image), the image note of an image that Pi cannot process,
 * and the notice for a first line that is larger than the byte limit. Pi's
 * continuation notice stays after the numbered lines, without a number.
 *
 * A numbered result gets details.lineNumbers = {first, count}. Pi catches an
 * error in a hook and keeps the result unchanged with no visible error.
 *
 * The rules follow Pi 0.84.1, dist/core/tools/read.js: the first line is
 * offset - 1 (at least 0, 0 without an offset), and Array.slice truncates a
 * fractional index.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const SEPARATOR = "│";
const IMAGE_NOTE = "Read image file [";
// The notice that Pi adds when the limit stops a read before the end of the file.
const MORE_LINES = /\n\n\[-?[\d.]+ more lines in file\. Use offset=-?[\d.]+ to continue\.\]$/;

type TextBlock = { type: string; text?: string };
type ReadEvent = {
  toolName: string;
  input: Record<string, unknown>;
  content: TextBlock[];
  details?: Record<string, any>;
  isError: boolean;
};

function numbered(lines: string[], first: number): string {
  return lines.map((line, index) => `${String(first + index).padStart(5)}${SEPARATOR}${line}`).join("\n");
}

export function numberReadResult(event: ReadEvent) {
  if (event.toolName !== "read" || event.isError) return undefined;
  if (!Array.isArray(event.content) || event.content.length !== 1) return undefined;
  const block = event.content[0];
  if (block?.type !== "text" || typeof block.text !== "string") return undefined;
  const text = block.text;
  const truncation = event.details?.truncation;
  if (truncation?.firstLineExceedsLimit) return undefined;
  if (!truncation && text.startsWith(IMAGE_NOTE)) return undefined;

  const offset = Number(event.input?.offset);
  const start = offset ? Math.max(0, offset - 1) : 0;
  const first = Math.trunc(start) + 1;
  let body = text;
  let notice = "";
  let lines: string[];
  if (truncation?.truncated && typeof truncation.content === "string" && text.startsWith(truncation.content)) {
    // Pi stopped at the line or byte limit: each element is a line of the file.
    body = truncation.content;
    notice = text.slice(body.length);
    lines = body.split("\n");
  } else {
    // Pi adds the notice only to a read with a limit.
    const more = event.input?.limit === undefined ? null : MORE_LINES.exec(text);
    if (more) {
      // The limit stopped the read: Array.slice(start, start + limit).
      body = text.slice(0, more.index);
      notice = text.slice(more.index);
      const count = Math.max(0, Math.trunc(start + Number(event.input?.limit)) - Math.trunc(start));
      lines = count === 0 ? [] : body.split("\n");
    } else {
      // The read reached the end of the file. The final empty element comes
      // from a newline at the end of the file: it is not a line.
      lines = body.split("\n");
      if (lines[lines.length - 1] === "") lines.pop();
    }
  }
  const tail = notice === "" && body.endsWith("\n") && lines.length > 0 ? "\n" : "";
  const result = lines.length === 0 ? body : numbered(lines, first) + tail;
  return {
    content: [{ type: "text", text: result + notice }],
    details: { ...(event.details ?? {}), lineNumbers: { first, count: lines.length } },
  };
}

export default function numberedRead(pi: ExtensionAPI) {
  pi.on("tool_result", (event) => numberReadResult(event as unknown as ReadEvent));
}
