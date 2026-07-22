# bash completion for mactriage                            -*- shell-script -*-

__mactriage_debug()
{
    if [[ -n ${BASH_COMP_DEBUG_FILE:-} ]]; then
        echo "$*" >> "${BASH_COMP_DEBUG_FILE}"
    fi
}

# Homebrew on Macs have version 1.3 of bash-completion which doesn't include
# _init_completion. This is a very minimal version of that function.
__mactriage_init_completion()
{
    COMPREPLY=()
    _get_comp_words_by_ref "$@" cur prev words cword
}

__mactriage_index_of_word()
{
    local w word=$1
    shift
    index=0
    for w in "$@"; do
        [[ $w = "$word" ]] && return
        index=$((index+1))
    done
    index=-1
}

__mactriage_contains_word()
{
    local w word=$1; shift
    for w in "$@"; do
        [[ $w = "$word" ]] && return
    done
    return 1
}

__mactriage_handle_go_custom_completion()
{
    __mactriage_debug "${FUNCNAME[0]}: cur is ${cur}, words[*] is ${words[*]}, #words[@] is ${#words[@]}"

    local shellCompDirectiveError=1
    local shellCompDirectiveNoSpace=2
    local shellCompDirectiveNoFileComp=4
    local shellCompDirectiveFilterFileExt=8
    local shellCompDirectiveFilterDirs=16

    local out requestComp lastParam lastChar comp directive args

    # Prepare the command to request completions for the program.
    # Calling ${words[0]} instead of directly mactriage allows handling aliases
    args=("${words[@]:1}")
    # Disable ActiveHelp which is not supported for bash completion v1
    requestComp="MACTRIAGE_ACTIVE_HELP=0 ${words[0]} __completeNoDesc ${args[*]}"

    lastParam=${words[$((${#words[@]}-1))]}
    lastChar=${lastParam:$((${#lastParam}-1)):1}
    __mactriage_debug "${FUNCNAME[0]}: lastParam ${lastParam}, lastChar ${lastChar}"

    if [ -z "${cur}" ] && [ "${lastChar}" != "=" ]; then
        # If the last parameter is complete (there is a space following it)
        # We add an extra empty parameter so we can indicate this to the go method.
        __mactriage_debug "${FUNCNAME[0]}: Adding extra empty parameter"
        requestComp="${requestComp} \"\""
    fi

    __mactriage_debug "${FUNCNAME[0]}: calling ${requestComp}"
    # Use eval to handle any environment variables and such
    out=$(eval "${requestComp}" 2>/dev/null)

    # Extract the directive integer at the very end of the output following a colon (:)
    directive=${out##*:}
    # Remove the directive
    out=${out%:*}
    if [ "${directive}" = "${out}" ]; then
        # There is not directive specified
        directive=0
    fi
    __mactriage_debug "${FUNCNAME[0]}: the completion directive is: ${directive}"
    __mactriage_debug "${FUNCNAME[0]}: the completions are: ${out}"

    if [ $((directive & shellCompDirectiveError)) -ne 0 ]; then
        # Error code.  No completion.
        __mactriage_debug "${FUNCNAME[0]}: received error from custom completion go code"
        return
    else
        if [ $((directive & shellCompDirectiveNoSpace)) -ne 0 ]; then
            if [[ $(type -t compopt) = "builtin" ]]; then
                __mactriage_debug "${FUNCNAME[0]}: activating no space"
                compopt -o nospace
            fi
        fi
        if [ $((directive & shellCompDirectiveNoFileComp)) -ne 0 ]; then
            if [[ $(type -t compopt) = "builtin" ]]; then
                __mactriage_debug "${FUNCNAME[0]}: activating no file completion"
                compopt +o default
            fi
        fi
    fi

    if [ $((directive & shellCompDirectiveFilterFileExt)) -ne 0 ]; then
        # File extension filtering
        local fullFilter filter filteringCmd
        # Do not use quotes around the $out variable or else newline
        # characters will be kept.
        for filter in ${out}; do
            fullFilter+="$filter|"
        done

        filteringCmd="_filedir $fullFilter"
        __mactriage_debug "File filtering command: $filteringCmd"
        $filteringCmd
    elif [ $((directive & shellCompDirectiveFilterDirs)) -ne 0 ]; then
        # File completion for directories only
        local subdir
        # Use printf to strip any trailing newline
        subdir=$(printf "%s" "${out}")
        if [ -n "$subdir" ]; then
            __mactriage_debug "Listing directories in $subdir"
            __mactriage_handle_subdirs_in_dir_flag "$subdir"
        else
            __mactriage_debug "Listing directories in ."
            _filedir -d
        fi
    else
        while IFS='' read -r comp; do
            COMPREPLY+=("$comp")
        done < <(compgen -W "${out}" -- "$cur")
    fi
}

__mactriage_handle_reply()
{
    __mactriage_debug "${FUNCNAME[0]}"
    local comp
    case $cur in
        -*)
            if [[ $(type -t compopt) = "builtin" ]]; then
                compopt -o nospace
            fi
            local allflags
            if [ ${#must_have_one_flag[@]} -ne 0 ]; then
                allflags=("${must_have_one_flag[@]}")
            else
                allflags=("${flags[*]} ${two_word_flags[*]}")
            fi
            while IFS='' read -r comp; do
                COMPREPLY+=("$comp")
            done < <(compgen -W "${allflags[*]}" -- "$cur")
            if [[ $(type -t compopt) = "builtin" ]]; then
                [[ "${COMPREPLY[0]}" == *= ]] || compopt +o nospace
            fi

            # complete after --flag=abc
            if [[ $cur == *=* ]]; then
                if [[ $(type -t compopt) = "builtin" ]]; then
                    compopt +o nospace
                fi

                local index flag
                flag="${cur%=*}"
                __mactriage_index_of_word "${flag}" "${flags_with_completion[@]}"
                COMPREPLY=()
                if [[ ${index} -ge 0 ]]; then
                    PREFIX=""
                    cur="${cur#*=}"
                    ${flags_completion[${index}]}
                    if [ -n "${ZSH_VERSION:-}" ]; then
                        # zsh completion needs --flag= prefix
                        eval "COMPREPLY=( \"\${COMPREPLY[@]/#/${flag}=}\" )"
                    fi
                fi
            fi

            if [[ -z "${flag_parsing_disabled}" ]]; then
                # If flag parsing is enabled, we have completed the flags and can return.
                # If flag parsing is disabled, we may not know all (or any) of the flags, so we fallthrough
                # to possibly call handle_go_custom_completion.
                return 0;
            fi
            ;;
    esac

    # check if we are handling a flag with special work handling
    local index
    __mactriage_index_of_word "${prev}" "${flags_with_completion[@]}"
    if [[ ${index} -ge 0 ]]; then
        ${flags_completion[${index}]}
        return
    fi

    # we are parsing a flag and don't have a special handler, no completion
    if [[ ${cur} != "${words[cword]}" ]]; then
        return
    fi

    local completions
    completions=("${commands[@]}")
    if [[ ${#must_have_one_noun[@]} -ne 0 ]]; then
        completions+=("${must_have_one_noun[@]}")
    elif [[ -n "${has_completion_function}" ]]; then
        # if a go completion function is provided, defer to that function
        __mactriage_handle_go_custom_completion
    fi
    if [[ ${#must_have_one_flag[@]} -ne 0 ]]; then
        completions+=("${must_have_one_flag[@]}")
    fi
    while IFS='' read -r comp; do
        COMPREPLY+=("$comp")
    done < <(compgen -W "${completions[*]}" -- "$cur")

    if [[ ${#COMPREPLY[@]} -eq 0 && ${#noun_aliases[@]} -gt 0 && ${#must_have_one_noun[@]} -ne 0 ]]; then
        while IFS='' read -r comp; do
            COMPREPLY+=("$comp")
        done < <(compgen -W "${noun_aliases[*]}" -- "$cur")
    fi

    if [[ ${#COMPREPLY[@]} -eq 0 ]]; then
        if declare -F __mactriage_custom_func >/dev/null; then
            # try command name qualified custom func
            __mactriage_custom_func
        else
            # otherwise fall back to unqualified for compatibility
            declare -F __custom_func >/dev/null && __custom_func
        fi
    fi

    # available in bash-completion >= 2, not always present on macOS
    if declare -F __ltrim_colon_completions >/dev/null; then
        __ltrim_colon_completions "$cur"
    fi

    # If there is only 1 completion and it is a flag with an = it will be completed
    # but we don't want a space after the =
    if [[ "${#COMPREPLY[@]}" -eq "1" ]] && [[ $(type -t compopt) = "builtin" ]] && [[ "${COMPREPLY[0]}" == --*= ]]; then
       compopt -o nospace
    fi
}

# The arguments should be in the form "ext1|ext2|extn"
__mactriage_handle_filename_extension_flag()
{
    local ext="$1"
    _filedir "@(${ext})"
}

__mactriage_handle_subdirs_in_dir_flag()
{
    local dir="$1"
    pushd "${dir}" >/dev/null 2>&1 && _filedir -d && popd >/dev/null 2>&1 || return
}

__mactriage_handle_flag()
{
    __mactriage_debug "${FUNCNAME[0]}: c is $c words[c] is ${words[c]}"

    # if a command required a flag, and we found it, unset must_have_one_flag()
    local flagname=${words[c]}
    local flagvalue=""
    # if the word contained an =
    if [[ ${words[c]} == *"="* ]]; then
        flagvalue=${flagname#*=} # take in as flagvalue after the =
        flagname=${flagname%=*} # strip everything after the =
        flagname="${flagname}=" # but put the = back
    fi
    __mactriage_debug "${FUNCNAME[0]}: looking for ${flagname}"
    if __mactriage_contains_word "${flagname}" "${must_have_one_flag[@]}"; then
        must_have_one_flag=()
    fi

    # if you set a flag which only applies to this command, don't show subcommands
    if __mactriage_contains_word "${flagname}" "${local_nonpersistent_flags[@]}"; then
      commands=()
    fi

    # keep flag value with flagname as flaghash
    # flaghash variable is an associative array which is only supported in bash > 3.
    if [[ -z "${BASH_VERSION:-}" || "${BASH_VERSINFO[0]:-}" -gt 3 ]]; then
        if [ -n "${flagvalue}" ] ; then
            flaghash[${flagname}]=${flagvalue}
        elif [ -n "${words[ $((c+1)) ]}" ] ; then
            flaghash[${flagname}]=${words[ $((c+1)) ]}
        else
            flaghash[${flagname}]="true" # pad "true" for bool flag
        fi
    fi

    # skip the argument to a two word flag
    if [[ ${words[c]} != *"="* ]] && __mactriage_contains_word "${words[c]}" "${two_word_flags[@]}"; then
        __mactriage_debug "${FUNCNAME[0]}: found a flag ${words[c]}, skip the next argument"
        c=$((c+1))
        # if we are looking for a flags value, don't show commands
        if [[ $c -eq $cword ]]; then
            commands=()
        fi
    fi

    c=$((c+1))

}

__mactriage_handle_noun()
{
    __mactriage_debug "${FUNCNAME[0]}: c is $c words[c] is ${words[c]}"

    if __mactriage_contains_word "${words[c]}" "${must_have_one_noun[@]}"; then
        must_have_one_noun=()
    elif __mactriage_contains_word "${words[c]}" "${noun_aliases[@]}"; then
        must_have_one_noun=()
    fi

    nouns+=("${words[c]}")
    c=$((c+1))
}

__mactriage_handle_command()
{
    __mactriage_debug "${FUNCNAME[0]}: c is $c words[c] is ${words[c]}"

    local next_command
    if [[ -n ${last_command} ]]; then
        next_command="_${last_command}_${words[c]//:/__}"
    else
        if [[ $c -eq 0 ]]; then
            next_command="_mactriage_root_command"
        else
            next_command="_${words[c]//:/__}"
        fi
    fi
    c=$((c+1))
    __mactriage_debug "${FUNCNAME[0]}: looking for ${next_command}"
    declare -F "$next_command" >/dev/null && $next_command
}

__mactriage_handle_word()
{
    if [[ $c -ge $cword ]]; then
        __mactriage_handle_reply
        return
    fi
    __mactriage_debug "${FUNCNAME[0]}: c is $c words[c] is ${words[c]}"
    if [[ "${words[c]}" == -* ]]; then
        __mactriage_handle_flag
    elif __mactriage_contains_word "${words[c]}" "${commands[@]}"; then
        __mactriage_handle_command
    elif [[ $c -eq 0 ]]; then
        __mactriage_handle_command
    elif __mactriage_contains_word "${words[c]}" "${command_aliases[@]}"; then
        # aliashash variable is an associative array which is only supported in bash > 3.
        if [[ -z "${BASH_VERSION:-}" || "${BASH_VERSINFO[0]:-}" -gt 3 ]]; then
            words[c]=${aliashash[${words[c]}]}
            __mactriage_handle_command
        else
            __mactriage_handle_noun
        fi
    else
        __mactriage_handle_noun
    fi
    __mactriage_handle_word
}

_mactriage_baseline_compare()
{
    last_command="mactriage_baseline_compare"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--only=")
    two_word_flags+=("--only")
    local_nonpersistent_flags+=("--only")
    local_nonpersistent_flags+=("--only=")
    flags+=("--skip=")
    two_word_flags+=("--skip")
    local_nonpersistent_flags+=("--skip")
    local_nonpersistent_flags+=("--skip=")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_baseline_delete()
{
    last_command="mactriage_baseline_delete"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--yes")
    local_nonpersistent_flags+=("--yes")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_baseline_help()
{
    last_command="mactriage_baseline_help"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    has_completion_function=1
    noun_aliases=()
}

_mactriage_baseline_list()
{
    last_command="mactriage_baseline_list"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_baseline_save()
{
    last_command="mactriage_baseline_save"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--only=")
    two_word_flags+=("--only")
    local_nonpersistent_flags+=("--only")
    local_nonpersistent_flags+=("--only=")
    flags+=("--skip=")
    two_word_flags+=("--skip")
    local_nonpersistent_flags+=("--skip")
    local_nonpersistent_flags+=("--skip=")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_baseline()
{
    last_command="mactriage_baseline"

    command_aliases=()

    commands=()
    commands+=("compare")
    commands+=("delete")
    commands+=("help")
    commands+=("list")
    commands+=("save")

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_collect()
{
    last_command="mactriage_collect"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--new-instance")
    local_nonpersistent_flags+=("--new-instance")
    flags+=("--no-launch")
    local_nonpersistent_flags+=("--no-launch")
    flags+=("--observe=")
    two_word_flags+=("--observe")
    local_nonpersistent_flags+=("--observe")
    local_nonpersistent_flags+=("--observe=")
    flags+=("--privileged")
    local_nonpersistent_flags+=("--privileged")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_compare()
{
    last_command="mactriage_compare"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_completion()
{
    last_command="mactriage_completion"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    must_have_one_noun+=("bash")
    must_have_one_noun+=("fish")
    must_have_one_noun+=("powershell")
    must_have_one_noun+=("zsh")
    noun_aliases=()
}

_mactriage_diagnose()
{
    last_command="mactriage_diagnose"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--new-instance")
    local_nonpersistent_flags+=("--new-instance")
    flags+=("--no-launch")
    local_nonpersistent_flags+=("--no-launch")
    flags+=("--observe=")
    two_word_flags+=("--observe")
    local_nonpersistent_flags+=("--observe")
    local_nonpersistent_flags+=("--observe=")
    flags+=("--privileged")
    local_nonpersistent_flags+=("--privileged")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_doctor()
{
    last_command="mactriage_doctor"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--fix")
    local_nonpersistent_flags+=("--fix")
    flags+=("--full")
    local_nonpersistent_flags+=("--full")
    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--only=")
    two_word_flags+=("--only")
    local_nonpersistent_flags+=("--only")
    local_nonpersistent_flags+=("--only=")
    flags+=("--profile=")
    two_word_flags+=("--profile")
    local_nonpersistent_flags+=("--profile")
    local_nonpersistent_flags+=("--profile=")
    flags+=("--quick")
    local_nonpersistent_flags+=("--quick")
    flags+=("--severity=")
    two_word_flags+=("--severity")
    local_nonpersistent_flags+=("--severity")
    local_nonpersistent_flags+=("--severity=")
    flags+=("--skip=")
    two_word_flags+=("--skip")
    local_nonpersistent_flags+=("--skip")
    local_nonpersistent_flags+=("--skip=")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_explain()
{
    last_command="mactriage_explain"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_hang()
{
    last_command="mactriage_hang"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--cpu-threshold=")
    two_word_flags+=("--cpu-threshold")
    local_nonpersistent_flags+=("--cpu-threshold")
    local_nonpersistent_flags+=("--cpu-threshold=")
    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--memory-threshold-mib=")
    two_word_flags+=("--memory-threshold-mib")
    local_nonpersistent_flags+=("--memory-threshold-mib")
    local_nonpersistent_flags+=("--memory-threshold-mib=")
    flags+=("--sample-output=")
    two_word_flags+=("--sample-output")
    local_nonpersistent_flags+=("--sample-output")
    local_nonpersistent_flags+=("--sample-output=")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_help()
{
    last_command="mactriage_help"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    has_completion_function=1
    noun_aliases=()
}

_mactriage_network()
{
    last_command="mactriage_network"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--detail")
    local_nonpersistent_flags+=("--detail")
    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_permissions()
{
    last_command="mactriage_permissions"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--lookback=")
    two_word_flags+=("--lookback")
    local_nonpersistent_flags+=("--lookback")
    local_nonpersistent_flags+=("--lookback=")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_relaunch()
{
    last_command="mactriage_relaunch"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--observe=")
    two_word_flags+=("--observe")
    local_nonpersistent_flags+=("--observe")
    local_nonpersistent_flags+=("--observe=")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_repair_help()
{
    last_command="mactriage_repair_help"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    has_completion_function=1
    noun_aliases=()
}

_mactriage_repair_syspolicyd()
{
    last_command="mactriage_repair_syspolicyd"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--yes")
    local_nonpersistent_flags+=("--yes")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_repair()
{
    last_command="mactriage_repair"

    command_aliases=()

    commands=()
    commands+=("help")
    commands+=("syspolicyd")

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_scan()
{
    last_command="mactriage_scan"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--limit=")
    two_word_flags+=("--limit")
    local_nonpersistent_flags+=("--limit")
    local_nonpersistent_flags+=("--limit=")
    flags+=("--workers=")
    two_word_flags+=("--workers")
    local_nonpersistent_flags+=("--workers")
    local_nonpersistent_flags+=("--workers=")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_schema()
{
    last_command="mactriage_schema"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_share()
{
    last_command="mactriage_share"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--copy")
    local_nonpersistent_flags+=("--copy")
    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_startup()
{
    last_command="mactriage_startup"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--fix")
    local_nonpersistent_flags+=("--fix")
    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_storage()
{
    last_command="mactriage_storage"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--details")
    local_nonpersistent_flags+=("--details")
    flags+=("--fix")
    local_nonpersistent_flags+=("--fix")
    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_summarize()
{
    last_command="mactriage_summarize"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_system()
{
    last_command="mactriage_system"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--top=")
    two_word_flags+=("--top")
    local_nonpersistent_flags+=("--top")
    local_nonpersistent_flags+=("--top=")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_version()
{
    last_command="mactriage_version"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_watch()
{
    last_command="mactriage_watch"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--cpu-threshold=")
    two_word_flags+=("--cpu-threshold")
    local_nonpersistent_flags+=("--cpu-threshold")
    local_nonpersistent_flags+=("--cpu-threshold=")
    flags+=("--duration=")
    two_word_flags+=("--duration")
    local_nonpersistent_flags+=("--duration")
    local_nonpersistent_flags+=("--duration=")
    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--include-paths")
    local_nonpersistent_flags+=("--include-paths")
    flags+=("--interval=")
    two_word_flags+=("--interval")
    local_nonpersistent_flags+=("--interval")
    local_nonpersistent_flags+=("--interval=")
    flags+=("--memory-free-threshold=")
    two_word_flags+=("--memory-free-threshold")
    local_nonpersistent_flags+=("--memory-free-threshold")
    local_nonpersistent_flags+=("--memory-free-threshold=")
    flags+=("--memory-threshold-mib=")
    two_word_flags+=("--memory-threshold-mib")
    local_nonpersistent_flags+=("--memory-threshold-mib")
    local_nonpersistent_flags+=("--memory-threshold-mib=")
    flags+=("--sockets-threshold=")
    two_word_flags+=("--sockets-threshold")
    local_nonpersistent_flags+=("--sockets-threshold")
    local_nonpersistent_flags+=("--sockets-threshold=")
    flags+=("--threads-threshold=")
    two_word_flags+=("--threads-threshold")
    local_nonpersistent_flags+=("--threads-threshold")
    local_nonpersistent_flags+=("--threads-threshold=")
    flags+=("--warn-growth=")
    two_word_flags+=("--warn-growth")
    local_nonpersistent_flags+=("--warn-growth")
    local_nonpersistent_flags+=("--warn-growth=")
    flags+=("--window=")
    two_word_flags+=("--window")
    local_nonpersistent_flags+=("--window")
    local_nonpersistent_flags+=("--window=")
    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_mactriage_root_command()
{
    last_command="mactriage"

    command_aliases=()

    commands=()
    commands+=("baseline")
    commands+=("collect")
    commands+=("compare")
    commands+=("completion")
    commands+=("diagnose")
    commands+=("doctor")
    commands+=("explain")
    commands+=("hang")
    commands+=("help")
    commands+=("network")
    commands+=("permissions")
    commands+=("relaunch")
    commands+=("repair")
    commands+=("scan")
    commands+=("schema")
    commands+=("share")
    commands+=("startup")
    commands+=("storage")
    commands+=("summarize")
    commands+=("system")
    commands+=("version")
    commands+=("watch")

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--accessible")
    flags+=("--animation=")
    two_word_flags+=("--animation")
    flags+=("--color=")
    two_word_flags+=("--color")
    flags+=("--fail-on=")
    two_word_flags+=("--fail-on")
    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--json")
    flags+=("--offline")
    flags+=("--output=")
    two_word_flags+=("--output")
    two_word_flags+=("-o")
    flags+=("--plain")
    flags+=("--redact=")
    two_word_flags+=("--redact")
    flags+=("--timeout=")
    two_word_flags+=("--timeout")
    flags+=("--total-timeout=")
    two_word_flags+=("--total-timeout")
    flags+=("--verbose")
    flags+=("-v")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

__start_mactriage()
{
    local cur prev words cword split
    declare -A flaghash 2>/dev/null || :
    declare -A aliashash 2>/dev/null || :
    if declare -F _init_completion >/dev/null 2>&1; then
        _init_completion -s || return
    else
        __mactriage_init_completion -n "=" || return
    fi

    local c=0
    local flag_parsing_disabled=
    local flags=()
    local two_word_flags=()
    local local_nonpersistent_flags=()
    local flags_with_completion=()
    local flags_completion=()
    local commands=("mactriage")
    local command_aliases=()
    local must_have_one_flag=()
    local must_have_one_noun=()
    local has_completion_function=""
    local last_command=""
    local nouns=()
    local noun_aliases=()

    __mactriage_handle_word
}

if [[ $(type -t compopt) = "builtin" ]]; then
    complete -o default -F __start_mactriage mactriage
else
    complete -o default -o nospace -F __start_mactriage mactriage
fi

# ex: ts=4 sw=4 et filetype=sh
