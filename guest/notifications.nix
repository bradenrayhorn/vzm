{ pkgs, ... }:
let
  notificationVsockPort = 3132;

  vzmNotify = pkgs.writeShellScriptBin "vzm-notify" ''
    set -euo pipefail

    usage() {
      echo "usage: vzm-notify send --from FROM --message MESSAGE" >&2
      echo "       vzm-notify acknowledge|ack" >&2
      exit 2
    }

    [ "$#" -ge 1 ] || usage
    action="$1"
    shift

    case "$action" in
      send)
        from=""
        message=""
        while [ "$#" -gt 0 ]; do
          [ "$#" -ge 2 ] || usage
          case "$1" in
            --from)
              from="$2"
              ;;
            --message)
              message="$2"
              ;;
            *)
              usage
              ;;
          esac
          shift 2
        done
        [ -n "$from" ] && [ -n "$message" ] || usage
        request="$(${pkgs.jq}/bin/jq -cn \
          --arg from "$from" \
          --arg message "$message" \
          '{action: "notify", from: $from, message: $message}')"
        ;;
      acknowledge|ack)
        [ "$#" -eq 0 ] || usage
        request='{"action":"acknowledge"}'
        ;;
      *)
        usage
        ;;
    esac

    printf '%s\n' "$request" \
      | ${pkgs.socat}/bin/socat -T 5 - VSOCK-CONNECT:2:${toString notificationVsockPort} \
      | ${pkgs.jq}/bin/jq -er '
          if .ok == true then
            "\(.pending) pending"
          else
            error(.error // "notification request failed")
          end
        '
  '';
in
{
  environment.systemPackages = [ vzmNotify ];
}
