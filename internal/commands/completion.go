package commands

import (
	"fmt"
	"os"
)

// CmdCompletion generates shell completion scripts
func CmdCompletion(args []string) {
	if len(args) == 0 {
		printCompletionUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "bash":
		fmt.Print(bashCompletion)
	case "zsh":
		fmt.Print(zshCompletion)
	case "fish":
		fmt.Print(fishCompletion)
	case "help", "--help", "-h":
		printCompletionUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown shell: %s\n", args[0])
		printCompletionUsage()
		os.Exit(1)
	}
}

func printCompletionUsage() {
	fmt.Println(`rvl completion - Generate shell completion scripts

Usage:
  rvl completion <shell>

Shells:
  bash    Generate bash completion script
  zsh     Generate zsh completion script
  fish    Generate fish completion script

Setup:
  # Bash (add to ~/.bashrc)
  eval "$(rvl completion bash)"

  # Zsh (add to ~/.zshrc)
  eval "$(rvl completion zsh)"

  # Fish
  rvl completion fish | source
  # Or persist:
  rvl completion fish > ~/.config/fish/completions/rvl.fish`)
}

const bashCompletion = `# rvl bash completion
_rvl() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    commands="init login logout status scan risk control knowledge evidence commands plugin completion config version help"

    case "${prev}" in
        rvl)
            COMPREPLY=( $(compgen -W "${commands}" -- "${cur}") )
            return 0
            ;;
        risk)
            COMPREPLY=( $(compgen -W "list show stale close resolve acknowledge accept" -- "${cur}") )
            return 0
            ;;
        control)
            COMPREPLY=( $(compgen -W "list show" -- "${cur}") )
            return 0
            ;;
        knowledge)
            COMPREPLY=( $(compgen -W "search procedures patterns" -- "${cur}") )
            return 0
            ;;
        evidence)
            COMPREPLY=( $(compgen -W "submit list verify" -- "${cur}") )
            return 0
            ;;
        commands)
            COMPREPLY=( $(compgen -W "--skills --agents" -- "${cur}") )
            return 0
            ;;
        plugin)
            COMPREPLY=( $(compgen -W "install update list remove" -- "${cur}") )
            return 0
            ;;
        install|remove)
            if [[ "${COMP_WORDS[COMP_CWORD-2]}" == "plugin" ]]; then
                COMPREPLY=( $(compgen -W "claude codex gemini cursor windsurf copilot augment" -- "${cur}") )
            fi
            return 0
            ;;
        config)
            COMPREPLY=( $(compgen -W "show set" -- "${cur}") )
            return 0
            ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "${cur}") )
            return 0
            ;;
    esac
}
complete -F _rvl rvl
`

const zshCompletion = `#compdef rvl

_rvl() {
    local -a commands
    commands=(
        'init:Initialize Revelara for this repository'
        'login:Configure credentials interactively'
        'logout:Remove stored credentials'
        'status:Check connection and authentication status'
        'scan:Submit risk findings to Revelara'
        'risk:Manage risk lifecycle'
        'control:Query reliability controls catalog'
        'knowledge:Query organizational knowledge base'
        'evidence:Manage control evidence'
        'commands:List available skills and agents'
        'plugin:Manage editor plugins'
        'completion:Generate shell completion scripts'
        'config:Manage configuration'
        'version:Show version information'
        'help:Show help message'
    )

    local -a risk_cmds control_cmds knowledge_cmds evidence_cmds plugin_cmds config_cmds completion_cmds commands_opts editors

    risk_cmds=('list' 'show' 'stale' 'close' 'resolve' 'acknowledge' 'accept')
    control_cmds=('list' 'show')
    knowledge_cmds=('search' 'procedures' 'patterns')
    evidence_cmds=('submit' 'list' 'verify')
    plugin_cmds=('install' 'update' 'list' 'remove')
    config_cmds=('show' 'set')
    completion_cmds=('bash' 'zsh' 'fish')
    commands_opts=('--skills' '--agents')
    editors=('claude' 'codex' 'gemini' 'cursor' 'windsurf' 'copilot' 'augment')

    if (( CURRENT == 2 )); then
        _describe 'command' commands
    elif (( CURRENT == 3 )); then
        case "${words[2]}" in
            risk)       compadd "${risk_cmds[@]}" ;;
            control)    compadd "${control_cmds[@]}" ;;
            knowledge)  compadd "${knowledge_cmds[@]}" ;;
            evidence)   compadd "${evidence_cmds[@]}" ;;
            plugin)     compadd "${plugin_cmds[@]}" ;;
            config)     compadd "${config_cmds[@]}" ;;
            completion) compadd "${completion_cmds[@]}" ;;
            commands)   compadd "${commands_opts[@]}" ;;
        esac
    elif (( CURRENT == 4 )); then
        case "${words[3]}" in
            install|remove)
                if [[ "${words[2]}" == "plugin" ]]; then
                    compadd "${editors[@]}"
                fi
                ;;
        esac
    fi
}

_rvl "$@"
`

const fishCompletion = `# rvl fish completion

# Disable file completions by default
complete -c rvl -f

# Top-level commands
complete -c rvl -n "__fish_use_subcommand" -a "init" -d "Initialize Revelara for this repository"
complete -c rvl -n "__fish_use_subcommand" -a "login" -d "Configure credentials interactively"
complete -c rvl -n "__fish_use_subcommand" -a "logout" -d "Remove stored credentials"
complete -c rvl -n "__fish_use_subcommand" -a "status" -d "Check connection and authentication status"
complete -c rvl -n "__fish_use_subcommand" -a "scan" -d "Submit risk findings to Revelara"
complete -c rvl -n "__fish_use_subcommand" -a "risk" -d "Manage risk lifecycle"
complete -c rvl -n "__fish_use_subcommand" -a "control" -d "Query reliability controls catalog"
complete -c rvl -n "__fish_use_subcommand" -a "knowledge" -d "Query organizational knowledge base"
complete -c rvl -n "__fish_use_subcommand" -a "evidence" -d "Manage control evidence"
complete -c rvl -n "__fish_use_subcommand" -a "commands" -d "List available skills and agents"
complete -c rvl -n "__fish_use_subcommand" -a "plugin" -d "Manage editor plugins"
complete -c rvl -n "__fish_use_subcommand" -a "completion" -d "Generate shell completion scripts"
complete -c rvl -n "__fish_use_subcommand" -a "config" -d "Manage configuration"
complete -c rvl -n "__fish_use_subcommand" -a "version" -d "Show version information"
complete -c rvl -n "__fish_use_subcommand" -a "help" -d "Show help message"

# risk subcommands
complete -c rvl -n "__fish_seen_subcommand_from risk" -a "list" -d "List risks"
complete -c rvl -n "__fish_seen_subcommand_from risk" -a "show" -d "Show risk details"
complete -c rvl -n "__fish_seen_subcommand_from risk" -a "stale" -d "List stale risks"
complete -c rvl -n "__fish_seen_subcommand_from risk" -a "close" -d "Close a risk"
complete -c rvl -n "__fish_seen_subcommand_from risk" -a "resolve" -d "Mark risk as resolved"
complete -c rvl -n "__fish_seen_subcommand_from risk" -a "acknowledge" -d "Acknowledge risks"
complete -c rvl -n "__fish_seen_subcommand_from risk" -a "accept" -d "Accept risk"

# control subcommands
complete -c rvl -n "__fish_seen_subcommand_from control" -a "list" -d "List controls"
complete -c rvl -n "__fish_seen_subcommand_from control" -a "show" -d "Show control details"

# knowledge subcommands
complete -c rvl -n "__fish_seen_subcommand_from knowledge" -a "search" -d "Search knowledge base"
complete -c rvl -n "__fish_seen_subcommand_from knowledge" -a "procedures" -d "List procedures"
complete -c rvl -n "__fish_seen_subcommand_from knowledge" -a "patterns" -d "List patterns"

# evidence subcommands
complete -c rvl -n "__fish_seen_subcommand_from evidence" -a "submit" -d "Submit evidence"
complete -c rvl -n "__fish_seen_subcommand_from evidence" -a "list" -d "List evidence"
complete -c rvl -n "__fish_seen_subcommand_from evidence" -a "verify" -d "Verify evidence"

# commands options
complete -c rvl -n "__fish_seen_subcommand_from commands" -l "skills" -d "Show only skills"
complete -c rvl -n "__fish_seen_subcommand_from commands" -l "agents" -d "Show only agents"

# plugin subcommands
complete -c rvl -n "__fish_seen_subcommand_from plugin" -a "install" -d "Install plugin for editor"
complete -c rvl -n "__fish_seen_subcommand_from plugin" -a "update" -d "Update plugin(s)"
complete -c rvl -n "__fish_seen_subcommand_from plugin" -a "list" -d "List installed plugins"
complete -c rvl -n "__fish_seen_subcommand_from plugin" -a "remove" -d "Remove installed plugin"

# config subcommands
complete -c rvl -n "__fish_seen_subcommand_from config" -a "show" -d "Show configuration"
complete -c rvl -n "__fish_seen_subcommand_from config" -a "set" -d "Set a configuration value"

# completion subcommands
complete -c rvl -n "__fish_seen_subcommand_from completion" -a "bash" -d "Generate bash completions"
complete -c rvl -n "__fish_seen_subcommand_from completion" -a "zsh" -d "Generate zsh completions"
complete -c rvl -n "__fish_seen_subcommand_from completion" -a "fish" -d "Generate fish completions"
`
