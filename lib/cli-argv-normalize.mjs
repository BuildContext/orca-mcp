/**
 * CLI argv normalize parity with shipped Orca CLI v1.4.182.
 *
 * Bridge ownership must evaluate the SAME argv the CLI will see after
 * normalizeCommandPositionals promotes leftover positionals onto flags.
 * This reimplements parseArgs + normalizeCommandPositionals against a
 * pinned snapshot of the shipped specs and BOOLEAN_FLAGS.
 *
 * Differential tests fail if a future CLI adds a positional/flag the table lacks.
 *
 * Pin history: tables were authored against AppImage v1.4.180. On 2026-08-15
 * they were diffed against live `/opt/orca/orca-linux.AppImage` v1.4.182
 * (`args.js` GLOBAL_FLAGS + BOOLEAN_FLAGS, and `specs/` COMMAND_SPECS
 * path / allowedFlags / positionalArgs / aliases). The tables are identical
 * — version string only; no flag or spec edits.
 */

/** @typedef {{ path: string[], positionalArgs?: string[], aliases?: string[][], allowedFlags?: string[] }} CliCommandSpec */

export const CLI_SPEC_VERSION = "1.4.182"; // tables identical to 1.4.180 (diffed 2026-08-15)

export const GLOBAL_FLAGS = Object.freeze(["help","json","pairing-code","environment"]);

export const BOOLEAN_FLAGS = Object.freeze(new Set(["all","attachments","children","comments","connect","current","dry-run","enter","focus","force","full","help","inject","include-archived","include-visual-layouts","interrupt","json","local","messages","me","mobile","mobile-pairing","no-pairing","parent-current","provision","ready","recipe-json","relations","reinstall","restore-window","return-preamble","run-hooks","show-profile","staged","tab","tasks","text-stdin","unread","value-stdin","wait"]));

/** Pinned command specs from AppImage v1.4.182 (identical to the 1.4.180 dump). */
export const CLI_COMMAND_SPECS = Object.freeze(
  [{"path":["account","add"],"allowedFlags":["help","json","pairing-code","environment","agent"]},{"path":["account","list"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["agent","hooks","status"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["agent","hooks","off"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["agent","hooks","on"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["artifacts","share"],"positionalArgs":["file"],"allowedFlags":["help","json","pairing-code","environment","api-url","file"]},{"path":["artifacts","update"],"positionalArgs":["file"],"allowedFlags":["help","json","pairing-code","environment","api-url","file"]},{"path":["artifacts","unshare"],"positionalArgs":["file"],"allowedFlags":["help","json","pairing-code","environment","api-url","file"]},{"path":["artifacts","list"],"allowedFlags":["help","json","pairing-code","environment","api-url","cursor"]},{"path":["artifacts","delete"],"positionalArgs":["id"],"aliases":[["artifacts","rm"]],"allowedFlags":["help","json","pairing-code","environment","api-url","id"]},{"path":["automations","list"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["automations","show"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","id"]},{"path":["automations","create"],"allowedFlags":["help","json","pairing-code","environment","name","prompt","provider","precheck","precheck-timeout","repo","workspace","project","host","project-host-setup","source-context","workspace-mode","base-branch","trigger","schedule","time","day","timezone","enabled","disabled","missed-run-grace-minutes","reuse-session","fresh-session"]},{"path":["automations","edit"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","id","name","prompt","provider","precheck","precheck-timeout","repo","workspace","project","host","project-host-setup","source-context","workspace-mode","base-branch","trigger","schedule","time","day","timezone","enabled","disabled","missed-run-grace-minutes","reuse-session","fresh-session"]},{"path":["automations","remove"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","id"]},{"path":["automations","run"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","id"]},{"path":["automations","runs"],"allowedFlags":["help","json","pairing-code","environment","id"]},{"path":["cookie","get"],"allowedFlags":["help","json","pairing-code","environment","url","worktree"]},{"path":["cookie","set"],"allowedFlags":["help","json","pairing-code","environment","name","value","domain","path","secure","httpOnly","sameSite","expires","worktree"]},{"path":["cookie","delete"],"allowedFlags":["help","json","pairing-code","environment","name","domain","url","worktree"]},{"path":["viewport"],"allowedFlags":["help","json","pairing-code","environment","width","height","scale","mobile","worktree"]},{"path":["geolocation"],"allowedFlags":["help","json","pairing-code","environment","latitude","longitude","accuracy","worktree"]},{"path":["intercept","enable"],"allowedFlags":["help","json","pairing-code","environment","patterns","worktree"]},{"path":["intercept","disable"],"allowedFlags":["help","json","pairing-code","environment","worktree"]},{"path":["intercept","list"],"allowedFlags":["help","json","pairing-code","environment","worktree"]},{"path":["capture","start"],"allowedFlags":["help","json","pairing-code","environment","worktree"]},{"path":["capture","stop"],"allowedFlags":["help","json","pairing-code","environment","worktree"]},{"path":["console"],"allowedFlags":["help","json","pairing-code","environment","limit","worktree"]},{"path":["network"],"allowedFlags":["help","json","pairing-code","environment","limit","worktree"]},{"path":["dblclick"],"allowedFlags":["help","json","pairing-code","environment","element","worktree"]},{"path":["forward"],"allowedFlags":["help","json","pairing-code","environment","worktree"]},{"path":["scrollintoview"],"allowedFlags":["help","json","pairing-code","environment","element","worktree"]},{"path":["get"],"allowedFlags":["help","json","pairing-code","environment","what","element","worktree"]},{"path":["is"],"allowedFlags":["help","json","pairing-code","environment","what","element","worktree"]},{"path":["inserttext"],"allowedFlags":["help","json","pairing-code","environment","text","worktree"]},{"path":["mouse","move"],"allowedFlags":["help","json","pairing-code","environment","x","y","worktree"]},{"path":["mouse","down"],"allowedFlags":["help","json","pairing-code","environment","button","worktree"]},{"path":["mouse","up"],"allowedFlags":["help","json","pairing-code","environment","button","worktree"]},{"path":["mouse","wheel"],"allowedFlags":["help","json","pairing-code","environment","dy","dx","worktree"]},{"path":["find"],"allowedFlags":["help","json","pairing-code","environment","locator","value","action","text","worktree"]},{"path":["set","device"],"allowedFlags":["help","json","pairing-code","environment","name","worktree"]},{"path":["set","offline"],"allowedFlags":["help","json","pairing-code","environment","state","worktree"]},{"path":["set","headers"],"allowedFlags":["help","json","pairing-code","environment","headers","worktree"]},{"path":["set","credentials"],"allowedFlags":["help","json","pairing-code","environment","user","pass","worktree"]},{"path":["set","media"],"allowedFlags":["help","json","pairing-code","environment","color-scheme","reduced-motion","worktree"]},{"path":["clipboard","read"],"allowedFlags":["help","json","pairing-code","environment","worktree"]},{"path":["clipboard","write"],"allowedFlags":["help","json","pairing-code","environment","text","worktree"]},{"path":["dialog","accept"],"allowedFlags":["help","json","pairing-code","environment","text","worktree"]},{"path":["dialog","dismiss"],"allowedFlags":["help","json","pairing-code","environment","worktree"]},{"path":["storage","local","get"],"allowedFlags":["help","json","pairing-code","environment","key","worktree"]},{"path":["storage","local","set"],"allowedFlags":["help","json","pairing-code","environment","key","value","worktree"]},{"path":["storage","local","clear"],"allowedFlags":["help","json","pairing-code","environment","worktree"]},{"path":["storage","session","get"],"allowedFlags":["help","json","pairing-code","environment","key","worktree"]},{"path":["storage","session","set"],"allowedFlags":["help","json","pairing-code","environment","key","value","worktree"]},{"path":["storage","session","clear"],"allowedFlags":["help","json","pairing-code","environment","worktree"]},{"path":["download"],"allowedFlags":["help","json","pairing-code","environment","selector","path","worktree"]},{"path":["highlight"],"allowedFlags":["help","json","pairing-code","environment","selector","worktree"]},{"path":["snapshot"],"allowedFlags":["help","json","pairing-code","environment","worktree"]},{"path":["screenshot"],"allowedFlags":["help","json","pairing-code","environment","format","worktree"]},{"path":["click"],"allowedFlags":["help","json","pairing-code","environment","element","worktree"]},{"path":["fill"],"allowedFlags":["help","json","pairing-code","environment","element","value","worktree"]},{"path":["type"],"allowedFlags":["help","json","pairing-code","environment","input","worktree"]},{"path":["select"],"allowedFlags":["help","json","pairing-code","environment","element","value","worktree"]},{"path":["scroll"],"allowedFlags":["help","json","pairing-code","environment","direction","amount","worktree"]},{"path":["goto"],"allowedFlags":["help","json","pairing-code","environment","url","worktree"]},{"path":["back"],"allowedFlags":["help","json","pairing-code","environment","worktree"]},{"path":["reload"],"allowedFlags":["help","json","pairing-code","environment","worktree"]},{"path":["eval"],"allowedFlags":["help","json","pairing-code","environment","expression","worktree"]},{"path":["wait"],"allowedFlags":["help","json","pairing-code","environment","selector","timeout","text","url","load","fn","state","worktree"]},{"path":["check"],"allowedFlags":["help","json","pairing-code","environment","element","worktree"]},{"path":["uncheck"],"allowedFlags":["help","json","pairing-code","environment","element","worktree"]},{"path":["focus"],"allowedFlags":["help","json","pairing-code","environment","element","worktree"]},{"path":["clear"],"allowedFlags":["help","json","pairing-code","environment","element","worktree"]},{"path":["select-all"],"allowedFlags":["help","json","pairing-code","environment","element","worktree"]},{"path":["keypress"],"allowedFlags":["help","json","pairing-code","environment","key","worktree"]},{"path":["pdf"],"allowedFlags":["help","json","pairing-code","environment","worktree"]},{"path":["full-screenshot"],"allowedFlags":["help","json","pairing-code","environment","format","worktree"]},{"path":["hover"],"allowedFlags":["help","json","pairing-code","environment","element","worktree"]},{"path":["drag"],"allowedFlags":["help","json","pairing-code","environment","from","to","worktree"]},{"path":["upload"],"allowedFlags":["help","json","pairing-code","environment","element","files","worktree"]},{"path":["tab","list"],"allowedFlags":["help","json","pairing-code","environment","worktree","show-profile"]},{"path":["tab","show"],"allowedFlags":["help","json","pairing-code","environment","page","worktree"]},{"path":["tab","current"],"allowedFlags":["help","json","pairing-code","environment","worktree"]},{"path":["tab","switch"],"allowedFlags":["help","json","pairing-code","environment","index","page","worktree","focus"]},{"path":["tab","create"],"allowedFlags":["help","json","pairing-code","environment","url","worktree","profile"]},{"path":["tab","profile","list"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["tab","profile","create"],"allowedFlags":["help","json","pairing-code","environment","label","scope","no-ua-spoof"]},{"path":["tab","profile","delete"],"allowedFlags":["help","json","pairing-code","environment","profile"]},{"path":["tab","profile","set"],"allowedFlags":["help","json","pairing-code","environment","profile","page","worktree"]},{"path":["tab","profile","show"],"allowedFlags":["help","json","pairing-code","environment","page","worktree"]},{"path":["tab","profile","use-default"],"allowedFlags":["help","json","pairing-code","environment","page","worktree"]},{"path":["tab","profile","clone"],"allowedFlags":["help","json","pairing-code","environment","profile","page","worktree"]},{"path":["tab","close"],"allowedFlags":["help","json","pairing-code","environment","index","worktree"]},{"path":["exec"],"allowedFlags":["help","json","pairing-code","environment","command","worktree"]},{"path":["computer","capabilities"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["computer","list-apps"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["computer","permissions"],"allowedFlags":["help","json","pairing-code","environment","id"]},{"path":["computer","list-windows"],"allowedFlags":["help","json","pairing-code","environment","app"]},{"path":["computer","get-app-state"],"allowedFlags":["help","json","pairing-code","environment","worktree","session","app","window-id","window-index","restore-window","no-screenshot"]},{"path":["computer","click"],"allowedFlags":["help","json","pairing-code","environment","worktree","session","app","window-id","window-index","restore-window","no-screenshot","element-index","x","y","click-count","mouse-button","modifiers"]},{"path":["computer","perform-secondary-action"],"allowedFlags":["help","json","pairing-code","environment","worktree","session","app","window-id","window-index","restore-window","no-screenshot","element-index","action"]},{"path":["computer","scroll"],"allowedFlags":["help","json","pairing-code","environment","worktree","session","app","window-id","window-index","restore-window","no-screenshot","element-index","x","y","direction","pages"]},{"path":["computer","drag"],"allowedFlags":["help","json","pairing-code","environment","worktree","session","app","window-id","window-index","restore-window","no-screenshot","from-element-index","to-element-index","from-x","from-y","to-x","to-y"]},{"path":["computer","type-text"],"allowedFlags":["help","json","pairing-code","environment","worktree","session","app","window-id","window-index","restore-window","no-screenshot","text","text-stdin"]},{"path":["computer","press-key"],"allowedFlags":["help","json","pairing-code","environment","worktree","session","app","window-id","window-index","restore-window","no-screenshot","key"]},{"path":["computer","hotkey"],"allowedFlags":["help","json","pairing-code","environment","worktree","session","app","window-id","window-index","restore-window","no-screenshot","key"]},{"path":["computer","paste-text"],"allowedFlags":["help","json","pairing-code","environment","worktree","session","app","window-id","window-index","restore-window","no-screenshot","text","text-stdin"]},{"path":["computer","set-value"],"allowedFlags":["help","json","pairing-code","environment","worktree","session","app","window-id","window-index","restore-window","no-screenshot","element-index","value","value-stdin"]},{"path":["open"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["serve"],"allowedFlags":["help","json","pairing-code","environment","port","pairing-address","mobile-pairing","no-pairing","project-root","recipe-json"]},{"path":["status"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["claude-teams"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["repo","list"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["repo","add"],"allowedFlags":["help","json","pairing-code","environment","path"]},{"path":["repo","show"],"allowedFlags":["help","json","pairing-code","environment","repo"]},{"path":["repo","set-base-ref"],"allowedFlags":["help","json","pairing-code","environment","repo","ref"]},{"path":["repo","search-refs"],"allowedFlags":["help","json","pairing-code","environment","repo","query","limit"]},{"path":["worktree","list"],"allowedFlags":["help","json","pairing-code","environment","repo","limit"]},{"path":["worktree","show"],"allowedFlags":["help","json","pairing-code","environment","worktree"]},{"path":["worktree","current"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["worktree","create"],"allowedFlags":["help","json","pairing-code","environment","repo","project","host","project-host-setup","name","agent","prompt","base-branch","issue","linear-issue","comment","setup","parent-worktree","no-parent","run-hooks","activate"]},{"path":["worktree","set"],"allowedFlags":["help","json","pairing-code","environment","worktree","display-name","issue","linear-issue","comment","workspace-status","parent-worktree","no-parent"]},{"path":["worktree","rm"],"aliases":[["worktree","remove"],["worktree","delete"]],"allowedFlags":["help","json","pairing-code","environment","worktree","force","run-hooks"]},{"path":["worktree","ps"],"allowedFlags":["help","json","pairing-code","environment","limit"]},{"path":["terminal","list"],"allowedFlags":["help","json","pairing-code","environment","worktree","limit","include-visual-layouts"]},{"path":["terminal","show"],"allowedFlags":["help","json","pairing-code","environment","terminal"]},{"path":["terminal","read"],"allowedFlags":["help","json","pairing-code","environment","terminal","cursor","limit"]},{"path":["terminal","send"],"allowedFlags":["help","json","pairing-code","environment","terminal","text","enter","interrupt"]},{"path":["terminal","wait"],"allowedFlags":["help","json","pairing-code","environment","terminal","for","timeout-ms"]},{"path":["terminal","stop"],"allowedFlags":["help","json","pairing-code","environment","worktree"]},{"path":["terminal","create"],"allowedFlags":["help","json","pairing-code","environment","worktree","command","title","focus"]},{"path":["terminal","switch"],"aliases":[["terminal","focus"]],"allowedFlags":["help","json","pairing-code","environment","terminal"]},{"path":["terminal","close"],"allowedFlags":["help","json","pairing-code","environment","terminal","tab"]},{"path":["terminal","rename"],"allowedFlags":["help","json","pairing-code","environment","terminal","title"]},{"path":["terminal","split"],"allowedFlags":["help","json","pairing-code","environment","terminal","direction","command"]},{"path":["diagnostics","memory"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["emulator","list"],"allowedFlags":["help","json","pairing-code","environment","worktree"]},{"path":["emulator","devices"],"allowedFlags":["help","json","pairing-code","environment","worktree"]},{"path":["emulator","attach"],"positionalArgs":["device"],"allowedFlags":["help","json","pairing-code","environment","worktree","focus","device"]},{"path":["emulator","tap"],"positionalArgs":["x","y"],"allowedFlags":["help","json","pairing-code","environment","device","emulator","worktree","x","y"]},{"path":["emulator","type"],"positionalArgs":["text"],"allowedFlags":["help","json","pairing-code","environment","text","device","emulator","worktree"]},{"path":["emulator","gesture"],"positionalArgs":["points"],"allowedFlags":["help","json","pairing-code","environment","points","device","emulator","worktree"]},{"path":["emulator","button"],"positionalArgs":["name"],"allowedFlags":["help","json","pairing-code","environment","device","emulator","worktree","name"]},{"path":["emulator","rotate"],"positionalArgs":["orientation"],"allowedFlags":["help","json","pairing-code","environment","device","emulator","worktree","orientation"]},{"path":["emulator","exec"],"allowedFlags":["help","json","pairing-code","environment","command","device","emulator","worktree"]},{"path":["emulator","kill"],"allowedFlags":["help","json","pairing-code","environment","device","emulator","worktree"]},{"path":["emulator","shutdown"],"allowedFlags":["help","json","pairing-code","environment","device","emulator","worktree"]},{"path":["emulator","install"],"positionalArgs":["path"],"allowedFlags":["help","json","pairing-code","environment","device","emulator","worktree","path","reinstall"]},{"path":["emulator","launch"],"positionalArgs":["package"],"allowedFlags":["help","json","pairing-code","environment","device","emulator","worktree","package","activity"]},{"path":["emulator","permissions"],"positionalArgs":["op","package","permission"],"allowedFlags":["help","json","pairing-code","environment","device","emulator","worktree","op","package","permission"]},{"path":["emulator","ax"],"allowedFlags":["help","json","pairing-code","environment","device","emulator","worktree"]},{"path":["emulator","logcat"],"allowedFlags":["help","json","pairing-code","environment","device","emulator","worktree","lines"]},{"path":["environment","add"],"allowedFlags":["help","json","pairing-code","environment","name"]},{"path":["environment","list"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["environment","show"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["environment","rm"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["file","open"],"positionalArgs":["path"],"allowedFlags":["help","json","pairing-code","environment","path","worktree"]},{"path":["file","diff"],"positionalArgs":["path"],"allowedFlags":["help","json","pairing-code","environment","path","staged","worktree"]},{"path":["file","open-changed"],"allowedFlags":["help","json","pairing-code","environment","mode","worktree"]},{"path":["project","list"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["project","setups"],"allowedFlags":["help","json","pairing-code","environment","project","host"]},{"path":["project","setup-existing-folder"],"allowedFlags":["help","json","pairing-code","environment","project","host","path","kind","display-name"]},{"path":["project","setup-clone"],"allowedFlags":["help","json","pairing-code","environment","project","host","url","destination","display-name"]},{"path":["project","setup-create"],"allowedFlags":["help","json","pairing-code","environment","project","host","setup-id","path","kind","display-name","worktree-base-path","git-username","state","method"]},{"path":["project","setup-update"],"allowedFlags":["help","json","pairing-code","environment","setup","display-name","path","worktree-base-path","git-username","kind","state","method"]},{"path":["project","setup-delete"],"allowedFlags":["help","json","pairing-code","environment","setup"]},{"path":["orchestration","run-create"],"allowedFlags":["help","json","pairing-code","environment","objective","from","retry-request"]},{"path":["orchestration","run-use"],"allowedFlags":["help","json","pairing-code","environment","id","from","takeover-legacy","retry-request"]},{"path":["orchestration","run-current"],"allowedFlags":["help","json","pairing-code","environment","from"]},{"path":["orchestration","run-list"],"allowedFlags":["help","json","pairing-code","environment","limit","cursor"]},{"path":["orchestration","run-show"],"allowedFlags":["help","json","pairing-code","environment","id"]},{"path":["orchestration","send"],"allowedFlags":["help","json","pairing-code","environment","to","run","from","subject","body","type","priority","thread-id","payload","task-id","dispatch-id","dispatch-capability","retry-request","outcome","files-modified","report-path","phase"]},{"path":["orchestration","check"],"allowedFlags":["help","json","pairing-code","environment","terminal","run","ack","unread","peek","all","types","format","wait","timeout-ms","retry-request"]},{"path":["orchestration","reply"],"allowedFlags":["help","json","pairing-code","environment","id","body","run","from","retry-request"]},{"path":["orchestration","inbox"],"allowedFlags":["help","json","pairing-code","environment","limit","terminal","full"]},{"path":["orchestration","task-create"],"allowedFlags":["help","json","pairing-code","environment","spec","task-title","display-name","deps","parent","run","from","retry-request"]},{"path":["orchestration","task-list"],"allowedFlags":["help","json","pairing-code","environment","status","ready","brief","run","from"]},{"path":["orchestration","task-update"],"allowedFlags":["help","json","pairing-code","environment","id","status","result","run","from","retry-request"]},{"path":["orchestration","worker-start"],"allowedFlags":["help","json","pairing-code","environment","task","on","worktree","name","repo","base-branch","display-name","comment","setup","agent","model","effort","terminal","retry-of","timeout-ms","run","from","retry-request"]},{"path":["orchestration","worker-show"],"allowedFlags":["help","json","pairing-code","environment","dispatch"]},{"path":["orchestration","worker-read"],"allowedFlags":["help","json","pairing-code","environment","dispatch","source","cursor","limit"]},{"path":["orchestration","worker-stop"],"allowedFlags":["help","json","pairing-code","environment","dispatch","retry-request"]},{"path":["orchestration","worker-abandon"],"allowedFlags":["help","json","pairing-code","environment","dispatch","retry-request"]},{"path":["orchestration","worker-release"],"allowedFlags":["help","json","pairing-code","environment","dispatch","retry-request"]},{"path":["orchestration","worker-retain"],"allowedFlags":["help","json","pairing-code","environment","dispatch","retry-request"]},{"path":["orchestration","worker-list"],"allowedFlags":["help","json","pairing-code","environment","run","terminal-state"]},{"path":["orchestration","dispatch"],"allowedFlags":["help","json","pairing-code","environment","task","to","from","run","inject","dry-run","return-preamble","retry-request"]},{"path":["orchestration","dispatch-show"],"allowedFlags":["help","json","pairing-code","environment","task","preamble","from"]},{"path":["orchestration","ask"],"allowedFlags":["help","json","pairing-code","environment","to","run","question","resume","dispatch-capability","options","timeout-ms","from","retry-request"]},{"path":["orchestration","coordinator-start"],"aliases":[["orchestration","run"]],"allowedFlags":["help","json","pairing-code","environment","spec","from","poll-interval-ms","max-concurrent","worktree"]},{"path":["orchestration","coordinator-stop"],"aliases":[["orchestration","run-stop"]],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["orchestration","gate-create"],"allowedFlags":["help","json","pairing-code","environment","task","question","options","from","retry-request"]},{"path":["orchestration","gate-resolve"],"allowedFlags":["help","json","pairing-code","environment","id","resolution","from","retry-request"]},{"path":["orchestration","gate-list"],"allowedFlags":["help","json","pairing-code","environment","task","status","run","from"]},{"path":["orchestration","reset"],"allowedFlags":["help","json","pairing-code","environment","all","tasks","messages","retry-request"]},{"path":["agent-context"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["linear","save-issue"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","current","team","title","description","body","body-file","state","assignee","priority","estimate","due-date","label","project","parent-id","write-id","workspace","id"]},{"path":["linear","list-issues"],"allowedFlags":["help","json","pairing-code","environment","team","cycle","label","limit","query","state","cursor","order-by","project","release","assignee","delegate","parent-id","priority","created-at","updated-at","include-archived","workspace"]},{"path":["linear","relation","add"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","current","related","type","workspace","id"]},{"path":["linear","relation","remove"],"positionalArgs":["id"],"aliases":[["linear","relation","rm"]],"allowedFlags":["help","json","pairing-code","environment","current","related","type","workspace","id"]},{"path":["linear","issue"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","current","comments","children","depth","attachments","relations","activity","full","workspace","id"]},{"path":["linear","search"],"positionalArgs":["query"],"allowedFlags":["help","json","pairing-code","environment","limit","workspace","query"]},{"path":["linear","team","list"],"allowedFlags":["help","json","pairing-code","environment","workspace"]},{"path":["linear","team","members"],"allowedFlags":["help","json","pairing-code","environment","team","workspace"]},{"path":["linear","team","states"],"allowedFlags":["help","json","pairing-code","environment","team","workspace"]},{"path":["linear","team","labels"],"allowedFlags":["help","json","pairing-code","environment","team","workspace"]},{"path":["linear","project","list"],"allowedFlags":["help","json","pairing-code","environment","query","limit","workspace"]},{"path":["linear","list"],"allowedFlags":["help","json","pairing-code","environment","filter","team","limit","workspace"]},{"path":["linear","status","set"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","current","to","workspace","id"]},{"path":["linear","assignee","set"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","current","me","to-id","workspace","id"]},{"path":["linear","assignee","clear"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","current","workspace","id"]},{"path":["linear","priority","set"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","current","to","workspace","id"]},{"path":["linear","priority","clear"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","current","workspace","id"]},{"path":["linear","estimate","set"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","current","to","workspace","id"]},{"path":["linear","estimate","clear"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","current","workspace","id"]},{"path":["linear","due-date","set"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","current","to","workspace","id"]},{"path":["linear","due-date","clear"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","current","workspace","id"]},{"path":["linear","label","add"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","current","label","workspace","id"]},{"path":["linear","label","remove"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","current","label","workspace","id"]},{"path":["linear","label","set"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","current","label","workspace","id"]},{"path":["linear","comment","add"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","current","body","body-file","reply-to","write-id","workspace","id"]},{"path":["linear","attach"],"positionalArgs":["id"],"allowedFlags":["help","json","pairing-code","environment","current","url","title","write-id","workspace","id"]},{"path":["linear","create"],"allowedFlags":["help","json","pairing-code","environment","title","body","body-file","team","project","state","assignee","priority","estimate","due-date","label","parent","parent-current","write-id","workspace"]},{"path":["vm","recipe","doctor"],"positionalArgs":["recipe-id"],"allowedFlags":["help","json","pairing-code","environment","recipe-id","repo-path","provision","connect"]},{"path":["skills","list"],"allowedFlags":["help","json","pairing-code","environment"]},{"path":["skills","get"],"positionalArgs":["topic"],"aliases":[["skills","show"]],"allowedFlags":["help","json","pairing-code","environment","topic","full"]},{"path":["skills","install"],"allowedFlags":["help","json","pairing-code","environment","skill","all","agent","local","dry-run"]},{"path":["skills","update"],"allowedFlags":["help","json","pairing-code","environment","skill","all","local","dry-run"]}].map((s) => Object.freeze(s)),
);

const REPEATABLE_STRING_FLAGS = new Set(['label', 'skill']);

function setFlagValue(flags, name, value) {
  const existing = flags.get(name);
  if (typeof existing === 'string' && REPEATABLE_STRING_FLAGS.has(name)) {
    flags.set(name, existing + '\u0000' + value);
    return;
  }
  flags.set(name, value);
}

function commandPathStartsAt(argv, tokenIndex, path) {
  let cursor = tokenIndex;
  for (const part of path) {
    while (argv[cursor]?.startsWith('--')) {
      const assignment = argv[cursor].slice(2);
      const flag = assignment.split('=', 1)[0];
      cursor += assignment.includes('=') || BOOLEAN_FLAGS.has(flag) ? 1 : 2;
    }
    if (argv[cursor] !== part) return false;
    cursor += 1;
  }
  return true;
}

function matches(actual, expected) {
  return actual.length === expected.length && actual.every((v, i) => v === expected[i]);
}

function specPaths(spec) {
  const out = [spec.path];
  if (Array.isArray(spec.aliases)) {
    for (const a of spec.aliases) out.push(a);
  }
  return out;
}

/**
 * @param {string[]} argv
 * @param {string[][]} [commandPaths]
 */
export function parseArgs(argv, commandPaths) {
  const commandPath = [];
  const flags = new Map();
  const list = Array.isArray(argv) ? argv.map(String) : [];
  for (let i = 0; i < list.length; i += 1) {
    const token = list[i];
    if (!token.startsWith('--')) {
      commandPath.push(token);
      continue;
    }
    const assignment = token.slice(2);
    const equalsIndex = assignment.indexOf('=');
    if (equalsIndex !== -1) {
      setFlagValue(flags, assignment.slice(0, equalsIndex), assignment.slice(equalsIndex + 1));
      continue;
    }
    const flag = assignment;
    if (BOOLEAN_FLAGS.has(flag)) {
      flags.set(flag, true);
      continue;
    }
    const startsCommandAt = (tokenIndex) =>
      commandPaths?.some((path) => commandPathStartsAt(list, tokenIndex, path)) ?? false;
    if (commandPath.length === 0 && startsCommandAt(i + 1) && !startsCommandAt(i + 2)) {
      flags.set(flag, true);
      continue;
    }
    const hasNext = i + 1 < list.length;
    const next = list[i + 1];
    if (!hasNext || next.startsWith('--')) {
      flags.set(flag, true);
      continue;
    }
    setFlagValue(flags, flag, next);
    i += 1;
  }
  return { commandPath, flags };
}

/**
 * @param {CliCommandSpec[]} specs
 * @param {{ commandPath: string[], flags: Map<string, unknown>, positionalFlagConflicts?: string[] }} parsed
 */
export function normalizeCommandPositionals(specs, parsed) {
  for (const spec of specs) {
    const positionalArgs = spec.positionalArgs ?? [];
    if (positionalArgs.length === 0 && !spec.aliases) continue;
    for (const base of specPaths(spec)) {
      const positionalCount = parsed.commandPath.length - base.length;
      if (positionalCount < 0 || positionalCount > positionalArgs.length) continue;
      if (!matches(parsed.commandPath.slice(0, base.length), base)) continue;
      const flags = new Map(parsed.flags);
      const values = parsed.commandPath.slice(base.length);
      const providedPositionals = values.map((_, index) => positionalArgs[index]);
      const positionalFlagConflicts = providedPositionals.filter((name) => flags.has(name));
      values.forEach((value, index) => {
        const name = positionalArgs[index];
        if (!flags.has(name)) flags.set(name, value);
      });
      return { commandPath: spec.path, flags, positionalFlagConflicts };
    }
  }
  return parsed;
}

/**
 * Promote leftover positionals onto flags WITHOUT collapsing duplicate flags.
 * Ownership deny-any requires every --terminal/--worktree occurrence to remain.
 * Only appends flags that normalize would add and raw argv lacks.
 *
 * @param {unknown} argv
 * @param {CliCommandSpec[]} [specs]
 * @returns {string[]}
 */
export function normalizeArgvForPolicy(argv, specs = CLI_COMMAND_SPECS) {
  if (!Array.isArray(argv) || argv.length === 0) return Array.isArray(argv) ? [...argv] : [];
  const raw = argv.map(String);
  const commandPaths = [];
  for (const s of specs) {
    for (const p of specPaths(s)) commandPaths.push(p);
  }
  const parsed = parseArgs(raw, commandPaths);
  const normalized = normalizeCommandPositionals(specs, parsed);
  // Start from the original argv so duplicate selectors survive.
  const out = [...raw];
  const hasFlag = (name) => {
    const needle = '--' + name;
    const needleEq = needle + '=';
    return out.some((t) => {
      const tok = String(t);
      return tok === needle || tok.startsWith(needleEq);
    });
  };
  for (const [name, value] of normalized.flags) {
    if (hasFlag(name)) continue; // already present (possibly multiple times)
    if (value === true) {
      out.push('--' + name);
    } else if (typeof value === 'string') {
      if (value.includes('\u0000')) {
        for (const part of value.split('\u0000')) out.push('--' + name, part);
      } else {
        out.push('--' + name, value);
      }
    } else if (value != null) {
      out.push('--' + name, String(value));
    }
  }
  return out;
}

export function normalizedFlagRecord(argv, specs = CLI_COMMAND_SPECS) {
  if (!Array.isArray(argv)) return { commandPath: [], flags: {} };
  const raw = argv.map(String);
  const commandPaths = [];
  for (const s of specs) for (const p of specPaths(s)) commandPaths.push(p);
  const parsed = parseArgs(raw, commandPaths);
  const normalized = normalizeCommandPositionals(specs, parsed);
  /** @type {Record<string, unknown>} */
  const flags = {};
  for (const [k, v] of normalized.flags) flags[k] = v;
  return { commandPath: [...normalized.commandPath], flags };
}

/** @param {CliCommandSpec[]} [specs] */
export function allSpecAllowedFlagNames(specs = CLI_COMMAND_SPECS) {
  const names = new Set(GLOBAL_FLAGS.map((f) => f.toLowerCase()));
  for (const f of BOOLEAN_FLAGS) names.add(String(f).toLowerCase());
  for (const s of specs) {
    for (const f of s.allowedFlags || []) names.add(String(f).toLowerCase());
    for (const p of s.positionalArgs || []) names.add(String(p).toLowerCase());
  }
  return names;
}

/**
 * Spec-derived list-shaped orchestration commands.
 * @param {CliCommandSpec[]} [specs]
 */
export function listShapedOrchestrationCommands(specs = CLI_COMMAND_SPECS) {
  /** @type {Array<{ path: string[], scopeFlags: string[] }>} */
  const out = [];
  for (const s of specs) {
    if (!s.path || s.path[0] !== 'orchestration') continue;
    const last = s.path[s.path.length - 1] || '';
    if (!(last === 'list' || last.endsWith('-list') || last === 'runs')) continue;
    const scopeFlags = (s.allowedFlags || []).filter((f) =>
      ['run', 'id', 'task', 'task-id', 'terminal', 'dispatch', 'dispatch-id', 'worktree'].includes(f),
    );
    out.push({ path: [...s.path], scopeFlags });
  }
  const seen = new Set();
  return out.filter((e) => {
    const k = e.path.join(' ');
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
