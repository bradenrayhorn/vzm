{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.vzm.proxy;
  caBundle = "/run/vzm/ca-bundle.pem";
  javaTruststore = "/run/vzm/java-truststore.jks";
  javaTrustOpts = lib.concatStringsSep " " [
    "-Djavax.net.ssl.trustStore=${javaTruststore}"
    "-Djavax.net.ssl.trustStorePassword=changeit"
    "-Djavax.net.ssl.trustStoreType=JKS"
  ];
  baseProxyEnv = {
    SSL_CERT_FILE = caBundle;
    NIX_SSL_CERT_FILE = caBundle;
    GIT_SSL_CAINFO = caBundle;
    REQUESTS_CA_BUNDLE = caBundle;
    NODE_EXTRA_CA_CERTS = caBundle;
  };
  proxyEnv =
    baseProxyEnv
    // lib.optionalAttrs cfg.java.enable {
      JAVA_TOOL_OPTIONS = javaTrustOpts;
      GRADLE_OPTS = javaTrustOpts;
    };
  systemdDefaultEnvironment = lib.concatStringsSep " " (
    lib.mapAttrsToList (name: value: "${name}=${value}") baseProxyEnv
  );
  forcedCertProxyEnv = proxyEnv // {
    SSL_CERT_FILE = lib.mkForce proxyEnv.SSL_CERT_FILE;
    NIX_SSL_CERT_FILE = lib.mkForce proxyEnv.NIX_SSL_CERT_FILE;
    GIT_SSL_CAINFO = lib.mkForce proxyEnv.GIT_SSL_CAINFO;
    REQUESTS_CA_BUNDLE = lib.mkForce proxyEnv.REQUESTS_CA_BUNDLE;
    NODE_EXTRA_CA_CERTS = lib.mkForce proxyEnv.NODE_EXTRA_CA_CERTS;
  };
in
{
  options.vzm.proxy.java.enable = lib.mkEnableOption "Java MITM CA truststore support";

  config = {
    environment.variables = forcedCertProxyEnv;
    environment.etc = {
      "ssl/certs/ca-certificates.crt".source = lib.mkForce caBundle;
      "ssl/certs/ca-bundle.crt".source = lib.mkForce caBundle;
      "pki/tls/certs/ca-bundle.crt".source = lib.mkForce caBundle;
    };

    nix.settings.extra-sandbox-paths = [
      caBundle
      "/run/vzm/mitm-ca.crt.pem"
    ]
    ++ lib.optional cfg.java.enable javaTruststore;

    # Preserve CA trust for root-side nixos-rebuild fetches as well.
    security.sudo.extraConfig = ''
      Defaults env_keep += "SSL_CERT_FILE NIX_SSL_CERT_FILE GIT_SSL_CAINFO REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS"
      ${lib.optionalString cfg.java.enable ''Defaults env_keep += "JAVA_TOOL_OPTIONS GRADLE_OPTS"''}
    '';

    systemd.services.vzm-mitm-ca = {
      description = "Fetch VZM MITM proxy CA";
      wantedBy = [ "multi-user.target" ];
      before = [
        "nix-daemon.service"
      ];
      path = [
        pkgs.coreutils
        pkgs.gnugrep
        pkgs.socat
      ];
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
        cat ${config.security.pki.caBundle} /run/vzm/mitm-ca.crt.pem.tmp > /run/vzm/ca-bundle.pem.tmp
        install -m 0644 /run/vzm/ca-bundle.pem.tmp /run/vzm/ca-bundle.pem
        rm -f /run/vzm/ca-bundle.pem.tmp

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
      "network-online.target"
    ];
    systemd.services.nix-daemon.after = [
      "vzm-mitm-ca.service"
      "network-online.target"
    ];
  };
}
