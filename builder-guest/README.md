# builder-guest

A self-contained NixOS guest that acts as the Linux builder for `vzm` root bundles.

It is intentionally separate from the normal `vzm` VM/root store logic because it bootstraps the Linux guests that `vzm` later runs.

Build attribute, from a Linux/aarch64-capable builder:

```sh
nix build .#builder-guest-bundle
```

The result is a vzm root bundle with:

- `kernel`
- `initrd`
- `rootfs.squashfs`
- `manifest.json`

The Swift host is implemented as:

```sh
cd ../vzm
./run-signed build-root ../guest --output /tmp/guest-bundle
```

At runtime `vzm build-root` attaches:

- the builder `rootfs.squashfs` read-only as `/dev/vda`
- a blank writable work disk as `/dev/vdb`
- a virtiofs share tagged `vzm-builder`
- a NAT network device

See `PLAN.md` for the host-side contract and request format.
