{
  inputs.nixpkgs.url = "nixpkgs";

  outputs = {
    self,
    nixpkgs,
    ...
  }: let
    version = builtins.substring 0 7 self.lastModifiedDate;

    systems = [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ];

    forAllSystems = nixpkgs.lib.genAttrs systems;
    nixpkgsFor = forAllSystems (system: import nixpkgs {inherit system;});

    packageFn = pkgs:
      pkgs.rustPlatform.buildRustPackage {
        pname = "quiclime";
        inherit version;

        src = builtins.path {
          name = "source";
          path = ./.;
        };

        cargoLock = {
          lockFile = ./Cargo.lock;
        };

        separateDebugInfo = true;
      };
  in rec {
    packages = forAllSystems (s: let
      pkgs = nixpkgsFor.${s};
    in rec {
      quiclime = packageFn pkgs;
      default = quiclime;
    });

    devShells = forAllSystems (s: let
      pkgs = nixpkgsFor.${s};
      inherit (pkgs) mkShell;
    in {
      default = mkShell {
        packages = with pkgs; [rustc cargo rustfmt];
      };
    });

    nixosModules = rec {
      quiclime = { config, lib, pkgs, ... }:
      with lib;
      let
        cfg = config.services.quiclime;
      in {
        options = {
          services.quiclime = {
            enable =
              mkEnableOption "Enable Quiclime relay server";

            package = mkOption {
              default = packages.${pkgs.system}.quiclime;
              type = types.package;
              defaultText = literalExpression "packages.${pkgs.system}.quiclime";
              description = lib.mdDoc "Quiclime derivation to use";
            };

            user = mkOption {
              type = types.str;
              default = "quiclime";
              description = lib.mdDoc "User account under which quiclime runs.";
            };

            group = mkOption {
              type = types.str;
              default = "quiclime";
              description = lib.mdDoc "Group under which quiclime runs.";
            };
            
            baseDomain = mkOption {
              type = types.str;
              description = lib.mdDoc "The base domain for this relay.";
            };
            
            mcAddr = mkOption {
              type = types.str;
              default = "[::]:25565";
              description = lib.mdDoc "The socket address to listen to Minecraft connections.";
            };
            
            relayAddr = mkOption {
              type = types.str;
              default = "[::]:25575";
              description = lib.mdDoc "The socket address to listen to quiclime connections.";
            };
            
            controlAddr = mkOption {
              type = types.str;
              default = "127.0.0.1:25585";
              description = lib.mdDoc "The socket address to listen to HTTP control messages.";
            };

            cert = mkOption {
              type = types.str;
              example = "/path/to/fullchain.pem";
              description = lib.mdDoc "Path to TLS certificate to use for quiclime connections.";
            };

            key = mkOption {
              type = types.str;
              example = "/path/to/key.pem";
              description = lib.mdDoc "Path to TLS key to use for quiclime connections.";
            };

            clickhouseUrl = mkOption {
              type = types.str;
              example = "http://clickhouse:8123";
              description = lib.mdDoc "Clickhouse URL to submit metrics to.";
            };

            clickhouseUser = mkOption {
              type = types.str;
              example = "quiclime";
              description = lib.mdDoc "Clickhouse user.";
            };

            clickhousePasswordPath = mkOption {
              type = types.str;
              example = "/clickhouse_password";
              description = lib.mdDoc "Path to file containing the Clickhouse user's password.";
            };

            clickhouseDatabase = mkOption {
              type = types.str;
              example = "default";
              description = lib.mdDoc "Name of Clickhouse database.";
            };

            clickhouseTable = mkOption {
              type = types.str;
              example = "mc_connections";
              description = lib.mdDoc "Name of Clickhouse table.";
            };
          };
        };

        config = mkIf cfg.enable {
          systemd.services.quiclime = {
            wantedBy = [ "multi-user.target" ];
            after = [ "network-online.target" ];
            wants = [ "network-online.target" ];
            description = "Quiclime relay server";
            serviceConfig = {
              Type = "simple";
              User = cfg.user;
              Group = cfg.group;
              ExecStart =
                "${cfg.package}/bin/quiclime";
              Restart = "on-failure";
              LimitNOFILE = "infinity";
            };

            environment = {
              QUICLIME_BASE_DOMAIN = cfg.baseDomain;
              QUICLIME_BIND_ADDR_MC = cfg.mcAddr;
              QUICLIME_BIND_ADDR_QUIC = cfg.relayAddr;
              QUICLIME_BIND_ADDR_WEB = cfg.controlAddr;
              QUICLIME_CERT_PATH = cfg.cert;
              QUICLIME_KEY_PATH = cfg.key;
              CLICKHOUSE_URL = cfg.clickhouseUrl;
              CLICKHOUSE_USER = cfg.clickhouseUser;
              CLICKHOUSE_PASSWORD_PATH = cfg.clickhousePasswordPath;
              CLICKHOUSE_DB = cfg.clickhouseDatabase;
              CLICKHOUSE_TABLE = cfg.clickhouseTable;
            };
          };

          users.users = mkIf (cfg.user == "quiclime") {
            quiclime = {
              description = "Quiclime relay server";
              useDefaultShell = true;
              group = cfg.group;
              isSystemUser = true;
            };
          };

          users.groups = mkIf (cfg.group == "quiclime") {
            quiclime = {};
          };
        };
      };
      default = quiclime;
    };
  };
}