/**
 * Repository guard for the agent of SentryTower.
 *
 * The audited code is untrusted input for the model. This tool_call hook
 * keeps the read, grep, find and ls tools of an audit session in two places:
 * the audited repository (the working folder of the session) and the Pi
 * package (the documentation path that the Pi system prompt shows). It
 * refuses a call whose path is outside these places after symbolic links:
 * for example /proc/1/environ, a home folder, or a link in the repository
 * that points out of it. A refused call gets an error result, and the
 * session goes on.
 *
 * The hook resolves a path as Pi 0.84.1 does (dist/utils/paths.js and
 * dist/core/tools/path-utils.js): Unicode spaces, a leading "@", "~", file
 * URLs, the working folder, and the file-name variants of the read tool. A
 * path that does not exist passes: the tool reports it. The hook changes no
 * tool, schema, description or system prompt, and no call that stays in
 * these places. An error in the hook refuses the call.
 */
import { existsSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const GUARDED_TOOLS = new Set(["read", "grep", "find", "ls"]);
const UNICODE_SPACES = /[  -   　]/g;
const NARROW_NO_BREAK_SPACE = " ";
export const REFUSAL = "Refused: the path is outside the repository under audit.";

type ToolCallEvent = { toolName: string; input?: Record<string, unknown> };

function normalize(value: string, argument: boolean): string {
  let text = argument ? value.replace(UNICODE_SPACES, " ") : value;
  if (argument && text.startsWith("@")) text = text.slice(1);
  const home = homedir();
  if (text === "~") return home;
  if (text.startsWith("~/")) return join(home, text.slice(2));
  if (/^file:\/\//.test(text)) return fileURLToPath(text);
  return text;
}

/** The absolute path of a tool argument, as Pi resolves it against the working folder. */
export function resolveLikePi(path: string, cwd: string): string {
  const value = normalize(path, true);
  return isAbsolute(value) ? resolve(value) : resolve(normalize(cwd, false), value);
}

/** The paths that the read tool tries, in its order: the path, then its file-name variants. */
export function readCandidates(resolved: string): string[] {
  const nfd = resolved.normalize("NFD");
  return [
    resolved,
    resolved.replace(/ (AM|PM)\./gi, `${NARROW_NO_BREAK_SPACE}$1.`),
    nfd,
    resolved.replace(/'/g, "’"),
    nfd.replace(/'/g, "’"),
  ];
}

function realPath(path: string): string | undefined {
  try {
    return realpathSync(path);
  } catch {
    return undefined;
  }
}

function inside(path: string, root: string): boolean {
  return path === root || path.startsWith(root.endsWith(sep) ? root : root + sep);
}

/** The places that the tools can reach, after symbolic links: the working folder and the Pi package. */
export function allowedRoots(cwd: string, packageDirectory?: string): string[] {
  const roots = [realPath(resolve(cwd)), packageDirectory ? realPath(packageDirectory) : undefined];
  return roots.filter((root): root is string => typeof root === "string" && root.length > 0);
}

/** The reason to refuse a tool call, or undefined when the call can run. */
export function checkToolCall(event: ToolCallEvent, cwd: string, roots: string[]): string | undefined {
  if (!GUARDED_TOOLS.has(event.toolName)) return undefined;
  const given = event.input?.path;
  // Pi validates the arguments first: a path that is not a string does not get here.
  if (given !== undefined && typeof given !== "string") return REFUSAL;
  const resolved = resolveLikePi(given || ".", cwd);
  const candidates = event.toolName === "read" ? readCandidates(resolved) : [resolved];
  const target = candidates.find((candidate) => existsSync(candidate));
  if (target === undefined) return undefined;
  const actual = realPath(target);
  if (actual === undefined) return REFUSAL;
  return roots.some((root) => inside(actual, root)) ? undefined : REFUSAL;
}

export default function repositoryGuard(pi: ExtensionAPI) {
  pi.on("tool_call", (event, ctx) => {
    try {
      const cwd = typeof ctx?.cwd === "string" && ctx.cwd ? ctx.cwd : process.cwd();
      const reason = checkToolCall(event as unknown as ToolCallEvent, cwd, allowedRoots(cwd, process.env.PI_PACKAGE_DIR));
      return reason === undefined ? undefined : { block: true, reason };
    } catch {
      return { block: true, reason: REFUSAL };
    }
  });
}
