{ lib, config, pkgs, ... }:

let
  cfg = config.ocf.graphical.greeter;

  startGreeter = pkgs.writeShellScript "start-ocf-greeter" ''
    systemd-cat -t ocf-greeter ${lib.getExe pkgs.ocf-greeter} \
      --default-session ${config.services.displayManager.defaultSession}
      ${lib.optionalString (cfg.background != null) "--background ${cfg.background}"}
      ${lib.optionalString (cfg.logo != null) "--logo ${cfg.logo}"}
  '';

  swayConfig = pkgs.writeText "sway-config" ''
    output * scale 2
    default_border none
    exec "${startGreeter}; swaymsg exit"
  '';
in
{
  options.ocf.graphical.greeter = {
    enable = lib.mkEnableOption "Enable OCF greetd greeter";
    background = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      description = "The background image to display";
      default = null;
    };
    logo = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      description = "The logo image to display";
      default = null;
    };
  };

  config = lib.mkIf cfg.enable {
    programs.sway.enable = true;

    services.greetd = {
      enable = true;
      settings.default_session = {
        command = "${lib.getExe pkgs.sway} --config ${swayConfig} --unsupported-gpu";
        user = "root";
      };
    };
  };
}
