# vzm guest builder plan

Goal: from macOS, run a short-lived Linux VM that builds a guest flake such as `../guest`, then writes a vzm root bundle (`kernel`, `initrd`, `rootfs.squashfs`, `manifest.json`) to a host directory.

## Shape

Keep the builder separate from the existing VM/root store code:

- `../builder-guest/` is a NixOS root bundle definition for the bootstrap builder VM.
- `vzm build-root` uses a dedicated Swift implementation in `Sources/Builder/`; it does not use `Runner`, `VMStore`, or `RootStore` to launch the builder VM.
- The only shared normal-runtime type is the root manifest structure used for bundle validation.

## Builder VM contract

The host launches the builder root with:

1. root bundle disk: `rootfs.squashfs` as read-only `/dev/vda`
2. fresh writable raw disk: `/dev/vdb` for the builder's `/nix/store` overlay upperdir/workdir
3. virtiofs share with tag `vzm-builder`, mounted in the guest at `/run/vzm-builder`
4. NAT network device, so `nix build` can fetch/substitute Linux inputs
5. serial console wired to stderr for logs

The virtiofs share contains:

```text
request.json
source/       # guest flake to build, or a read-only shared source mapped here
output/       # completed bundle is copied here
```

`request.json` schema:

```json
{
  "schemaVersion": 1,
  "sourceDir": "/run/vzm-builder/source",
  "attribute": "guest-bundle",
  "outputDir": "/run/vzm-builder/output"
}
```

The builder guest runs `vzm-builder-agent` at boot, performs:

```sh
nix build --out-link /run/vzm-builder/result /run/vzm-builder/source#guest-bundle
cp -L /run/vzm-builder/result/{kernel,initrd,manifest.json,rootfs.squashfs} /run/vzm-builder/output/
```

Then it writes `status.json` and powers off.

## Host-side implementation

`vzm build-root`:

1. Accepts a guest flake/source directory, default example `../guest`.
2. Accepts `--output PATH` for the bundle destination.
3. Accepts `--builder-root PATH`, defaulting to the nearest `builder-guest/result` found above the current directory.
4. Validates the builder bundle by loading its `manifest.json`; it does not use `RootStore`.
5. Creates a temporary workspace with `request.json`, `source/`, `output/`, and a sparse raw work disk.
6. Launches `VZVirtualMachine` with a builder-specific configuration:
   - `VZLinuxBootLoader` from the builder root manifest
   - read-only root squashfs block device
   - read/write work block device
   - `VZVirtioFileSystemDeviceConfiguration(tag: "vzm-builder")`
   - `VZVirtioNetworkDeviceConfiguration` using `VZNATNetworkDeviceAttachment`
7. Waits for `status.json` to appear, destructively stops the builder VM from the host, then reads `status.json` and fails if missing or non-zero.
8. Copies `output/` to the requested destination.
9. Leaves importing into `RootStore` as a separate step.

## Bootstrap flow

1. Build `../builder-guest#builder-guest-bundle` once on any Linux/aarch64-capable builder or CI.
2. Copy that bundle to macOS.
3. Run `vzm-guest-builder --builder-root /path/to/builder-bundle --source ../guest --output /tmp/guest-bundle`.
4. Import or run the produced guest bundle with existing vzm commands.

## Open decisions

- Whether the host should copy `source/` into the workspace or expose it read-only via `VZMultipleDirectoryShare`.
- Whether to keep a Nix binary cache between builds. The safest bootstrap design uses a fresh `/dev/vdb` per build.
- Whether `vzm build-root` should remain empty, wrap the separate executable, or be removed until the standalone builder is stable.
