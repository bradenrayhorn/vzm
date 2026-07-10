{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.vzm.proxy;
  proxyURL = "http://127.0.0.1:3128";
  caBundle = "/run/vzm/ca-bundle.pem";
  javaTruststore = "/run/vzm/java-truststore.jks";
  javaProxyOpts = lib.concatStringsSep " " [
    "-Dhttp.proxyHost=127.0.0.1"
    "-Dhttp.proxyPort=3128"
    "-Dhttps.proxyHost=127.0.0.1"
    "-Dhttps.proxyPort=3128"
  ];
  javaTrustOpts = lib.concatStringsSep " " [
    "-Djavax.net.ssl.trustStore=${javaTruststore}"
    "-Djavax.net.ssl.trustStorePassword=changeit"
    "-Djavax.net.ssl.trustStoreType=JKS"
  ];
  baseProxyEnv = {
    HTTPS_PROXY = proxyURL;
    https_proxy = proxyURL;
    HTTP_PROXY = proxyURL;
    http_proxy = proxyURL;
    NO_PROXY = "127.0.0.1,localhost";
    no_proxy = "127.0.0.1,localhost";
    SSL_CERT_FILE = caBundle;
    NIX_SSL_CERT_FILE = caBundle;
    CURL_CA_BUNDLE = caBundle;
    GIT_SSL_CAINFO = caBundle;
    REQUESTS_CA_BUNDLE = caBundle;
    NODE_EXTRA_CA_CERTS = caBundle;
  };
  proxyEnv = baseProxyEnv // lib.optionalAttrs cfg.java.enable {
    JAVA_TOOL_OPTIONS = "${javaTrustOpts} ${javaProxyOpts}";
    GRADLE_OPTS = "${javaTrustOpts} ${javaProxyOpts}";
  };
  systemdDefaultEnvironment = lib.concatStringsSep " " (
    lib.mapAttrsToList (name: value: "${name}=${value}") baseProxyEnv
  );
  forcedCertProxyEnv = proxyEnv // {
    SSL_CERT_FILE = lib.mkForce proxyEnv.SSL_CERT_FILE;
    NIX_SSL_CERT_FILE = lib.mkForce proxyEnv.NIX_SSL_CERT_FILE;
    CURL_CA_BUNDLE = lib.mkForce proxyEnv.CURL_CA_BUNDLE;
    GIT_SSL_CAINFO = lib.mkForce proxyEnv.GIT_SSL_CAINFO;
    REQUESTS_CA_BUNDLE = lib.mkForce proxyEnv.REQUESTS_CA_BUNDLE;
    NODE_EXTRA_CA_CERTS = lib.mkForce proxyEnv.NODE_EXTRA_CA_CERTS;
  };
in
{
  options.vzm.proxy.java.enable = lib.mkEnableOption "Java proxy and MITM CA truststore support";

  config = {
  environment.variables = forcedCertProxyEnv;
  nix.settings.extra-sandbox-paths = [
    caBundle
    "/run/vzm/mitm-ca.crt.pem"
  ] ++ lib.optional cfg.java.enable javaTruststore;

  # nixos-rebuild fetches flake inputs in the sudo/root client process before
  # nix-daemon builds anything. Preserve the proxy variables through sudo so
  # `sudo nixos-rebuild switch --flake ...` works without manually prefixing
  # the command with `sudo env ...`.
  security.sudo.extraConfig = ''
    Defaults env_keep += "HTTP_PROXY http_proxy HTTPS_PROXY https_proxy NO_PROXY no_proxy"
    Defaults env_keep += "SSL_CERT_FILE NIX_SSL_CERT_FILE CURL_CA_BUNDLE GIT_SSL_CAINFO REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS"
    ${lib.optionalString cfg.java.enable ''Defaults env_keep += "JAVA_TOOL_OPTIONS GRADLE_OPTS"''}
  '';

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

      ${lib.optionalString cfg.java.enable ''
        rm -f /run/vzm/java-truststore.jks.tmp
        ${pkgs.jdk21_headless}/bin/keytool \
          -importcert \
          -noprompt \
          -alias vzm-mitm-ca \
          -file /run/vzm/mitm-ca.crt.pem \
          -keystore /run/vzm/java-truststore.jks.tmp \
          -storepass changeit
        install -m 0644 /run/vzm/java-truststore.jks.tmp /run/vzm/java-truststore.jks
      ''}

      rm -f /run/vzm/mitm-ca.crt.pem.tmp /run/vzm/java-truststore.jks.tmp
    '';
  };

  systemd.user.extraConfig = ''
    DefaultEnvironment=${systemdDefaultEnvironment}
  '';

  systemd.services.nix-daemon.environment = forcedCertProxyEnv;
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
  };
}
