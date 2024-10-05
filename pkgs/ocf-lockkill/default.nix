{ lib, python3Packages, systemd }:

python3Packages.buildPythonApplication {
  pname = "ocf-lockkill";
  version = "2024-10-05";
  format = "other";

  src = ./.;

  installPhase = ''
    mkdir -p $out/bin
    cp lockkill $out/bin
  '';

  buildInputs = [ systemd ];

  meta = with lib; {
    description = "Daemon to kill locked sessions";
    homepage = "https://github.com/ocf/nix/tree/main/pkgs/ocf-lockkill";
    platforms = platforms.linux;
    mainProgram = "lockkill";
  };
}
