{ pkgs, ... }:
let
  gitProxyVsockPort = 4022;
  vzmGitSSH = pkgs.writeShellScriptBin "vzm-git-ssh" ''
    set -eu
    [ "$#" -eq 2 ] || exit 1
    case "$1" in git@*) host="''${1#git@}" ;; *) exit 1 ;; esac

    req="$2"; service="''${req%% *}"; repo="''${req#* }"
    repo="''${repo#\'}"; repo="''${repo%\'}"; repo="''${repo#/}"
    case "$service" in git-upload-pack|git-receive-pack) ;; *) exit 1 ;; esac

    payload="$service /$host:$repo"
    { printf '%04x%s\0' "$(( ''${#payload} + 5 ))" "$payload"; ${pkgs.coreutils}/bin/cat; } \
      | exec ${pkgs.socat}/bin/socat -t3600 - VSOCK-CONNECT:2:${toString gitProxyVsockPort}
  '';
in
{
  environment.etc."gitconfig".text = ''
[core]
  sshCommand = ${vzmGitSSH}/bin/vzm-git-ssh
[ssh]
  variant = simple
  '';
}
