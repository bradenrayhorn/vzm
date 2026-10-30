{ ... }:
{
  # This is a private NIC connected only to the host-side Go proxy, never NAT.
  # Keep addresses/MAC in sync with proxy/network.go and PrivateNetwork.swift.
  networking.useDHCP = false;
  networking.nameservers = [ "192.168.127.1" ];
  networking.enableIPv6 = false;
  boot.kernelModules = [ "virtio_net" ];

  systemd.network.enable = true;
  systemd.network.networks."10-vzm" = {
    matchConfig.MACAddress = "02:00:00:00:00:02";
    address = [ "192.168.127.2/24" ];
    routes = [ { Gateway = "192.168.127.1"; } ];
    networkConfig = {
      DHCP = "no";
      IPv6AcceptRA = false;
      LinkLocalAddressing = "no";
    };
    linkConfig.RequiredForOnline = "routable";
  };
}
