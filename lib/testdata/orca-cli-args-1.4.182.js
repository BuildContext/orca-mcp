// Vendored read-only extract of live AppImage v1.4.182
// /opt/orca/orca-linux.AppImage → resources/app.asar.unpacked/out/cli/args.js
// sha256: 3f156677981347fe92d81b89780940d7bd0890124e555825eb69072a6d18733d
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.REPEATED_FLAG_SEPARATOR = exports.BOOLEAN_FLAGS = exports.GLOBAL_FLAGS = exports.specPaths = void 0;
exports.parseArgs = parseArgs;
exports.resolveHelpPath = resolveHelpPath;
exports.matches = matches;
exports.supportsBrowserPageFlag = supportsBrowserPageFlag;
exports.effectiveAllowedFlags = effectiveAllowedFlags;
exports.isCommandGroup = isCommandGroup;
exports.normalizeCommandPositionals = normalizeCommandPositionals;
exports.findCommandSpec = findCommandSpec;
exports.validateCommandAndFlags = validateCommandAndFlags;
const types_1 = require("./runtime/types");
const command_suggestion_1 = require("./command-suggestion");
const command_spec_1 = require("./command-spec");
Object.defineProperty(exports, "specPaths", { enumerable: true, get: function () { return command_spec_1.specPaths; } });
exports.GLOBAL_FLAGS = ['help', 'json', 'pairing-code', 'environment'];
const GLOBAL_VALUE_FLAGS = new Set(['pairing-code', 'environment']);
exports.BOOLEAN_FLAGS = new Set([
    'all',
    'attachments',
    'children',
    'comments',
    'connect',
    'current',
    'dry-run',
    'enter',
    'focus',
    'force',
    'full',
    'help',
    'inject',
    'include-archived',
    'include-visual-layouts',
    'interrupt',
    'json',
    'local',
    'messages',
    'me',
    'mobile',
    'mobile-pairing',
    'no-pairing',
    'parent-current',
    'provision',
    'ready',
    'recipe-json',
    'relations',
    'reinstall',
    'restore-window',
    'return-preamble',
    'run-hooks',
    'show-profile',
    'staged',
    'tab',
    'tasks',
    'text-stdin',
    'unread',
    'value-stdin',
    'wait'
]);
exports.REPEATED_FLAG_SEPARATOR = '\u0000';
const REPEATABLE_STRING_FLAGS = new Set(['label', 'skill']);
function setFlagValue(flags, name, value) {
    const existing = flags.get(name);
    if (typeof existing === 'string' && REPEATABLE_STRING_FLAGS.has(name)) {
        flags.set(name, `${existing}${exports.REPEATED_FLAG_SEPARATOR}${value}`);
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
            cursor += assignment.includes('=') || exports.BOOLEAN_FLAGS.has(flag) ? 1 : 2;
        }
        if (argv[cursor] !== part) {
            return false;
        }
        cursor += 1;
    }
    return true;
}
function parseArgs(argv, commandPaths) {
    const commandPath = [];
    const flags = new Map();
    for (let i = 0; i < argv.length; i += 1) {
        const token = argv[i];
        if (!token.startsWith('--')) {
            commandPath.push(token);
            continue;
        }
        const assignment = token.slice(2);
        // Why: `--flag=value` is the only unambiguous way to pass a value that
        // itself starts with `--` (e.g. `--text=--help`); the space-separated form
        // treats a `--`-leading next token as a new flag, so it can't express one.
        const equalsIndex = assignment.indexOf('=');
        if (equalsIndex !== -1) {
            setFlagValue(flags, assignment.slice(0, equalsIndex), assignment.slice(equalsIndex + 1));
            continue;
        }
        const flag = assignment;
        if (exports.BOOLEAN_FLAGS.has(flag)) {
            flags.set(flag, true);
            continue;
        }
        // Why: a pre-command flag must not consume a registry-resolvable command path.
        const startsCommandAt = (tokenIndex) => commandPaths?.some((path) => commandPathStartsAt(argv, tokenIndex, path)) ?? false;
        if (commandPath.length === 0 && startsCommandAt(i + 1) && !startsCommandAt(i + 2)) {
            flags.set(flag, true);
            continue;
        }
        const hasNext = i + 1 < argv.length;
        const next = argv[i + 1];
        if (!hasNext || next.startsWith('--')) {
            flags.set(flag, true);
            continue;
        }
        setFlagValue(flags, flag, next);
        i += 1;
    }
    return { commandPath, flags };
}
function resolveHelpPath(parsed) {
    if (parsed.commandPath[0] === 'help') {
        return parsed.commandPath.slice(1);
    }
    if (parsed.flags.has('help')) {
        return parsed.commandPath;
    }
    return null;
}
function matches(actual, expected) {
    return (actual.length === expected.length && actual.every((value, index) => value === expected[index]));
}
function supportsBrowserPageFlag(commandPath) {
    const joined = commandPath.join(' ');
    if (['open', 'status'].includes(commandPath[0])) {
        return false;
    }
    if ([
        'account',
        'artifacts',
        'automations',
        'project',
        'repo',
        'worktree',
        'terminal',
        'file',
        'orchestration',
        'computer',
        'emulator',
        'note',
        'diagnostics',
        'linear',
        'skills',
        'agent-context'
    ].includes(commandPath[0])) {
        return false;
    }
    return ![
        'tab list',
        'tab create',
        'tab current',
        'tab profile list',
        'tab profile create',
        'tab profile delete'
    ].includes(joined);
}
// Why: validation and agent discovery must expose the same effective flag set.
function effectiveAllowedFlags(spec) {
    if (spec.argumentMode === 'passthrough') {
        return [];
    }
    return [
        ...new Set([
            ...exports.GLOBAL_FLAGS,
            ...spec.allowedFlags,
            ...(supportsBrowserPageFlag(spec.path) ? ['page'] : [])
        ])
    ];
}
function isCommandGroup(commandPath) {
    return ((commandPath.length === 1 &&
        [
            'account',
            'artifacts',
            'automations',
            'project',
            'repo',
            'worktree',
            'terminal',
            'file',
            'tab',
            'cookie',
            'intercept',
            'capture',
            'mouse',
            'set',
            'clipboard',
            'dialog',
            'storage',
            'orchestration',
            'computer',
            'emulator',
            'agent',
            'environment',
            'diagnostics',
            'linear',
            'skills',
            'vm'
        ].includes(commandPath[0])) ||
        (commandPath.length === 2 && commandPath[0] === 'agent' && commandPath[1] === 'hooks') ||
        (commandPath.length === 2 &&
            commandPath[0] === 'storage' &&
            ['local', 'session'].includes(commandPath[1])));
}
function normalizeCommandPositionals(specs, parsed) {
    for (const spec of specs) {
        const positionalArgs = spec.positionalArgs ?? [];
        // Why: aliased paths still need canonicalization when there are no positionals.
        if (positionalArgs.length === 0 && !spec.aliases) {
            continue;
        }
        // Why: canonicalize aliases before validation and dispatch so both use one key.
        for (const base of (0, command_spec_1.specPaths)(spec)) {
            // Why: `< 0` (not `<= 0`) so an exact base match with zero positionals
            // still canonicalizes an aliased path; upper bound guards over-consumption.
            const positionalCount = parsed.commandPath.length - base.length;
            if (positionalCount < 0 || positionalCount > positionalArgs.length) {
                continue;
            }
            if (!matches(parsed.commandPath.slice(0, base.length), base)) {
                continue;
            }
            const flags = new Map(parsed.flags);
            const values = parsed.commandPath.slice(base.length);
            // Why: validation runs inside main's error-reporting path, so normalization
            // records ambiguity instead of throwing before CLI errors can be formatted.
            const providedPositionals = values.map((_, index) => positionalArgs[index]);
            const positionalFlagConflicts = providedPositionals.filter((name) => flags.has(name));
            values.forEach((value, index) => {
                const name = positionalArgs[index];
                if (!flags.has(name)) {
                    flags.set(name, value);
                }
            });
            return { commandPath: spec.path, flags, positionalFlagConflicts };
        }
    }
    return parsed;
}
function findCommandSpec(specs, commandPath) {
    return specs.find((spec) => (0, command_spec_1.specPaths)(spec).some((candidate) => matches(candidate, commandPath)));
}
function validateCommandAndFlags(specs, parsed) {
    const spec = findCommandSpec(specs, parsed.commandPath);
    if (!spec) {
        throw new types_1.RuntimeClientError('invalid_argument', `Unknown command: ${parsed.commandPath.join(' ')}`, (0, command_suggestion_1.unknownCommandData)(specs, parsed.commandPath));
    }
    if (parsed.positionalFlagConflicts && parsed.positionalFlagConflicts.length > 0) {
        throw new types_1.RuntimeClientError('invalid_argument', `Pass ${parsed.positionalFlagConflicts
            .map((flag) => `--${flag}`)
            .join(', ')} either positionally or as a flag, not both.`);
    }
    const pageAllowed = supportsBrowserPageFlag(spec.path);
    for (const [flag, value] of parsed.flags) {
        const isGlobalFlag = exports.GLOBAL_FLAGS.includes(flag);
        if (GLOBAL_VALUE_FLAGS.has(flag) && (typeof value !== 'string' || value.length === 0)) {
            throw new types_1.RuntimeClientError('invalid_argument', `Flag --${flag} requires a value.`);
        }
        if (!isGlobalFlag && !spec.allowedFlags.includes(flag) && !(flag === 'page' && pageAllowed)) {
            throw new types_1.RuntimeClientError('invalid_argument', `Unknown flag --${flag} for command: ${spec.path.join(' ')}`, (0, command_suggestion_1.unknownFlagData)(flag, effectiveAllowedFlags(spec)));
        }
    }
}
