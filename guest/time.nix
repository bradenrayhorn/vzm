{ pkgs, ... }:
{
  systemd.services.vzm-time-sync = {
    description = "Synchronize guest clock from VZM host";
    wantedBy = [ "multi-user.target" ];
    before = [
      "nix-daemon.service"
      "vzm-mitm-ca.service"
      "vzm-https-proxy.service"
    ];
    path = [ pkgs.coreutils pkgs.gnugrep pkgs.socat ];
    serviceConfig.Type = "oneshot";
    script = ''
      set -eu

      until epoch=$(socat -T 5 - VSOCK-CONNECT:2:3131) \
        && echo "$epoch" | grep -Eq '^[0-9]{10,}$'; do
        sleep 0.2
      done

      date -u -s "@$epoch"
    '';
  };

  systemd.timers.vzm-time-sync = {
    description = "Periodically synchronize guest clock from VZM host";
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnUnitActiveSec = "1min";
      AccuracySec = "1min";
    };
  };
}
