{
  description = "NixOS desktop configuration for the Open Computing Facility";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
    nix-index-database = {
      url = "github:nix-community/nix-index-database";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    ocflib.url = "github:ocf/ocflib";
    ocf-sync-etc.url = "github:ocf/etc";
    ocf-pam-trimspaces.url = "github:ocf/pam_trimspaces";
    ocf-utils = {
      url = "github:ocf/utils";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    wayout = {
      url = "github:ocf/wayout";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self
    , nixpkgs
    , systems
    , nix-index-database
    , ocflib
    , ocf-sync-etc
    , ocf-pam-trimspaces
    , ocf-utils
    , wayout
    }@inputs:
    let
      # ============== #
      # Things to edit #
      # ============== #

      overlays = [
        self.overlays.default
        ocflib.overlays.default
        ocf-sync-etc.overlays.default
        ocf-pam-trimspaces.overlays.default
        nix-index-database.overlays.nix-index

        # GNOME 46: triple-buffering-v4-46
        # See: https://nixos.wiki/wiki/GNOME#Dynamic_triple_buffering
        (final: prev: {
          gnome = prev.gnome.overrideScope (gnomeFinal: gnomePrev: {
            mutter = gnomePrev.mutter.overrideAttrs (old: {
              src = final.fetchFromGitLab {
                domain = "gitlab.gnome.org";
                owner = "vanvugt";
                repo = "mutter";
                rev = "triple-buffering-v4-46";
                hash = "sha256-fkPjB/5DPBX06t7yj0Rb3UEuu5b9mu3aS+jhH18+lpI=";
              };
            });
          });
        })
      ];

      commonModules = [
        ./modules/ocf/auth.nix
        ./modules/ocf/browsers.nix
        ./modules/ocf/etc.nix
        ./modules/ocf/graphical.nix
        ./modules/ocf/kiosk.nix
        ./modules/ocf/kubernetes.nix
        ./modules/ocf/network.nix
        ./modules/ocf/shell.nix
        ./modules/ocf/tmpfs-home.nix
        ./profiles/base.nix
      ];

      defaultSystem = "x86_64-linux";
      overrideSystem = { overheat = "aarch64-linux"; };

      # ============== #
      # Glue/Internals #
      # ============== #

      pkgsFor = system: import nixpkgs {
        inherit overlays system;
        config = { allowUnfree = true; };
      };

      forAllSystems = fn: nixpkgs.lib.genAttrs
        (import systems)
        (system: fn (pkgsFor system));

      readGroup = group: nixpkgs.lib.mapAttrs'
        (filename: _: {
          name = nixpkgs.lib.nameFromURL filename ".";
          value = {
            inherit group;
            modules = [ ./hosts/${group}/${filename} ];
          };
        })
        (builtins.readDir ./hosts/${group});

      hosts = nixpkgs.lib.concatMapAttrs
        (group: _: readGroup group)
        (builtins.readDir ./hosts);

      colmenaHosts = builtins.mapAttrs
        (host: { modules, group }: {
          imports = commonModules ++ modules;
          deployment.tags = [ group ];
          deployment.targetHost = "${host}.ocf.berkeley.edu";
          deployment.targetUser = "root";
          deployment.allowLocalDeployment = true;
        })
        hosts;
    in
    {
      formatter = forAllSystems (pkgs: pkgs.nixpkgs-fmt);

      colmena = colmenaHosts // {
        meta = {
          nixpkgs = pkgsFor defaultSystem;
          nodeNixpkgs = nixpkgs.lib.mapAttrs (name: pkgsFor) overrideSystem;
          specialArgs = { inherit inputs; };
        };
      };

      packages = forAllSystems (pkgs: {
        bootstrap = pkgs.callPackage ./bootstrap { };
      });

      overlays.default = final: prev: {
        plasma-applet-commandoutput = final.callPackage ./pkgs/plasma-applet-commandoutput.nix { };
        catppuccin-sddm = final.qt6Packages.callPackage ./pkgs/catppuccin-sddm.nix { };
        ocf-utils = ocf-utils.packages.${final.system}.default;
        ocf-wayout = wayout.packages.${final.system}.default;
        ocf-papers = final.callPackage ./pkgs/ocf-papers.nix { };
        ocf-okular = final.callPackage ./pkgs/ocf-okular.nix { };
        ocf-lockkill = final.callPackage ./pkgs/ocf-lockkill { };
      };

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [ colmena git ];
        };
      });

      # We usually deploy hosts with colmena, but bootstrap currently uses the
      # nixosConfigurations flake output... this isn't exactly the same, because
      # colmena adds a couple of things to it, but it's OK for now...

      nixosConfigurations = builtins.mapAttrs
        (host: colmenaConfig: nixpkgs.lib.nixosSystem rec {
          system = overrideSystem.${host} or defaultSystem;
          pkgs = pkgsFor system;
          modules = colmenaConfig.imports;
          specialArgs = { inherit inputs; };
        })
        colmenaHosts;
    };
}
