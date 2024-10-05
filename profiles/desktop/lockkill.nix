{ pkgs, lib, ... }:

{
  systemd.services.lockkill = {
    description = "Daemon to kill locked sessions";
    after = [ "systemd-logind.service" ];
    partOf = [ "systemd-logind.service" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      ExecStart = lib.getExe pkgs.ocf-lockkill;
      Restart = "on-failure";

      ProtectSystem = "strict";
      ProtectHome = true;
      NoNewPrivileges = true;
    };
  };

  security.polkit.extraConfig = ''
    polkit.addRule(function(action, subject) {
      if ((action.id == "org.freedesktop.login1.manage"
        || action.id == "org.freedesktop.login1.lock-sessions")
        && subject.user == "ocflockkill")
      {
        return polkit.Result.YES;
      }
    });
  '';
}
