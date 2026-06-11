{ lib, pkgs, ... }:
let
  proxyURL = "http://127.0.0.1:3128";
  caBundle = "/run/vzm/ca-bundle.pem";
  proxyEnv = {
    HTTPS_PROXY = proxyURL;
    https_proxy = proxyURL;
    SSL_CERT_FILE = lib.mkForce caBundle;
    NIX_SSL_CERT_FILE = lib.mkForce caBundle;
    CURL_CA_BUNDLE = lib.mkForce caBundle;
    REQUESTS_CA_BUNDLE = lib.mkForce caBundle;
  };
in
{
  environment.variables = proxyEnv;

  systemd.services.vzm-mitm-ca = {
    description = "Fetch VZM MITM proxy CA";
    wantedBy = [ "multi-user.target" ];
    before = [
      "nix-daemon.service"
      "vzm-https-proxy.service"
    ];
    path = [ pkgs.coreutils pkgs.gnugrep pkgs.socat ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      set -eu
      mkdir -p /run/vzm

      until socat -T 5 - VSOCK-CONNECT:2:3129 > /run/vzm/mitm-ca.crt.pem.tmp \
        && test -s /run/vzm/mitm-ca.crt.pem.tmp \
        && grep -q -- "-----BEGIN CERTIFICATE-----" /run/vzm/mitm-ca.crt.pem.tmp \
        && grep -q -- "-----END CERTIFICATE-----" /run/vzm/mitm-ca.crt.pem.tmp; do
        rm -f /run/vzm/mitm-ca.crt.pem.tmp
        sleep 0.2
      done

      install -m 0644 /run/vzm/mitm-ca.crt.pem.tmp /run/vzm/mitm-ca.crt.pem
      install -m 0644 /run/vzm/mitm-ca.crt.pem.tmp /run/vzm/ca-bundle.pem
      rm -f /run/vzm/mitm-ca.crt.pem.tmp
    '';
  };

  systemd.services.nix-daemon.environment = proxyEnv;
  systemd.services.nix-daemon.wants = [
    "vzm-mitm-ca.service"
    "vzm-https-proxy.service"
  ];
  systemd.services.nix-daemon.after = [
    "vzm-mitm-ca.service"
    "vzm-https-proxy.service"
  ];

  systemd.services.vzm-https-proxy = {
    description = "VZM HTTPS proxy bridge";
    wantedBy = [ "multi-user.target" ];
    after = [ "vzm-mitm-ca.service" ];
    before = [
      "nix-daemon.service"
    ];
    serviceConfig = {
      Type = "simple";
      Restart = "always";
      RestartSec = "1s";
      ExecStart = "${pkgs.socat}/bin/socat TCP-LISTEN:3128,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:2:3128";
    };
  };
}
