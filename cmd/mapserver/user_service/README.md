The mapserver runs as a systemd user service.

The configuration of the service is on `~/.config/systemd/user/mapserver.service`
This service is configured as:
```
[Unit]
Description=FPKI Mapserver (user)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%h/fpki-config
ExecStart=%h/bin/mapserver %h/fpki-config/config.json
Restart=on-failure
RestartSec=5
Environment=GOMAXPROCS=2

[Install]
WantedBy=default.target
```

The service expects its configuration at `/fpki-config/config.json`.
Its contents are essentially the same as the sample config.


## CPU limitation
Because we run this user service mainly as a test, and only for the responder,
the `GOMAXPROCS` has been set to 2.


## Install and run systemd Service
To install the service and start it:
```
systemctl --user daemon-reload
systemctl --user enable --now mapserver.service
```

Start at boot without login (important on servers):
```
loginctl enable-linger $USER
```

General management:
```
systemctl --user status mapserver.service
systemctl --user restart mapserver.service
systemctl --user stop mapserver.service
journalctl --user -u mapserver.service -f
```
