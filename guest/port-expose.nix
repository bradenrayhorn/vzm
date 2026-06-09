{ pkgs, ... }:
let
  bridgeVsockPort = 4010;

  connectionBridge = pkgs.writeShellScript "vzm-port-expose-connection" ''
    set -eu

    IFS= read -r port || exit 1
    case "$port" in
      ""|*[!0-9]*) exit 1 ;;
    esac

    exec ${pkgs.socat}/bin/socat - "TCP-CONNECT:127.0.0.1:$port"
  '';
in
{
  systemd.services.vzm-port-expose = {
    description = "VZM guest port exposure bridge";
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" ];
    serviceConfig = {
      Type = "simple";
      Restart = "always";
      RestartSec = "1s";
      ExecStart = "${pkgs.socat}/bin/socat VSOCK-LISTEN:${toString bridgeVsockPort},reuseaddr,fork EXEC:${connectionBridge}";
    };
  };
}
