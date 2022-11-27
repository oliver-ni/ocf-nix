{
  description = "NixOS Configuration for the Open Computing Facility <https://ocf.berkeley.edu>";

  inputs = {
    # Pinned to NixOS 22.11 beta since that's coming out soon anyway
    nixpkgs.url = github:nixos/nixpkgs/22.11-beta;

    # Separate nixpkgs pin for Kubernetes (we don't want to accidentally update that)
    kubePin.url = github:nixos/nixpkgs/bb029673bface2fc9fb807f209f63ca06478a72d;

    # Some helper methods...
    flakeUtils.url = github:gytis-ivaskevicius/flake-utils-plus/v1.3.1;
  };

  outputs = { self, flakeUtils, kubePin, ... }@inputs:
    flakeUtils.lib.mkFlake {
      inherit self inputs;

      supportedSystems = [ "aarch64-linux" "x86_64-linux" ];
      channelsConfig.allowUnfree = true;

      # Packages to take from kubePin...
      channels.nixpkgs.overlaysBuilder = channels: [
        (final: prev: { inherit (channels.kubePin) cri-o; })
        (final: prev: { inherit (channels.kubePin) kubernetes; })
      ];

      # Things to pass into every host configuration...
      hostDefaults.modules = [ ./profiles/base.nix ./profiles/kubernetes ];

      # NixOS will compare the currently set hostname to hosts.* and apply the one that matches.
      hosts.adenine.modules = [ ./hosts/adenine.nix ]; # nucleus A
      hosts.guanine.modules = [ ./hosts/guanine.nix ]; # nucleus B
      hosts.cytosine.modules = [ ./hosts/cytosine.nix ]; # nucleus C
      hosts.thymine.modules = [ ./hosts/thymine.nix ]; # nucleus D
    };
}

