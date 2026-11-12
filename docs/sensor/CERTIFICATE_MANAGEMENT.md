# Sensor certificate management

The Vista Platform sensor authenticates to your platform with a client
certificate (mutual TLS). This page explains how it gets one, where it is kept,
how it is renewed, and how to recover when it is lost.

## Registration

The sensor registers itself on its first start; the installers never register on
its behalf. With the single-use registration key in its configuration, it:

1. generates a key pair on the host (the private key never leaves it);
2. creates a certificate signing request (CSR) for the UUID it proposes;
3. sends the registration key, the CSR and its metadata (name, address,
   platform, the version stamped into the binary, its capabilities);
4. receives, once the platform has checked the key, its signed client
   certificate, the platform CA and its sensor ID;
5. saves them and rewrites its configuration: `sensorId` becomes the UUID, a
   `security:` section records the certificate paths, and, once the platform has
   issued the sensor its own secret, the registration key is replaced by its
   SHA-256 (`registrationKeySha256`).

A registration key works once. After registration the sensor never needs it
again: on every start it loads its configuration and certificate from disk and
connects with mutual TLS.

## Where the certificate is kept

Under the data path (`storage.dataPath`):

```text
<dataPath>/
└── certs/            # directory 0700
    ├── client.crt    # the sensor's certificate (0644)
    ├── client.key    # its private key (0600)
    └── ca.crt        # the platform CA (0644)
```

| System | Data path of an installed sensor | Configuration file |
|---|---|---|
| Linux | `/opt/vista-sensor/data` | `/opt/vista-sensor/sensor-config.yaml` |
| macOS | `/usr/local/vista-sensor/data` | `/usr/local/vista-sensor/etc/sensor-config.yaml` |
| Windows | `%ProgramFiles%\VistaSensor\data` | `%ProgramFiles%\VistaSensor\sensor-config.yaml` |

After registration the configuration file looks like this (Linux example):

```yaml
sensorId: "550e8400-e29b-41d4-a716-446655440000"
controlPlaneUrl: "https://vista.example.com"
registrationKeySha256: "..."
# ... capture and storage settings ...
security:
  clientCertPath: "/opt/vista-sensor/data/certs/client.crt"
  clientKeyPath: "/opt/vista-sensor/data/certs/client.key"
  serverCACertPath: "/opt/vista-sensor/data/certs/ca.crt"
  useTLS: true
```

## File permissions

| File | Permissions | Why |
|---|---|---|
| `certs/` | `0700` | only the service account can reach the certificate files |
| `client.key` | `0600` | the private key authenticates the sensor |
| `client.crt`, `ca.crt` | `0644` | certificates hold no secret |
| `sensor-config.yaml` | `0600` (Linux, macOS); Administrators and SYSTEM only (Windows) | it holds the registration key until the sensor redeems it |

## Renewal

The sensor checks its certificate's expiry when it starts and every 24 hours.
When the certificate expires within 30 days, it asks the platform for a new one
and saves it; no key and no restart are needed.

## Troubleshooting

### The certificate has expired, or the platform no longer accepts it

A sensor whose certificate has expired, been revoked or been lost cannot renew
it itself, and its old registration key cannot be used again (keys are single-use,
and the configuration keeps only the key's hash). The supported recovery is to
register the host again:

1. In the console, open Discovery → Sensors & Agents and choose **Register
   sensor or agent** to create a **new** registration key.
2. Run the installer of the current release again with that key, as the
   console's commands show. A different key is a fresh registration: the
   installer discards the old certificate and the sensor registers as a new
   sensor.
3. Remove the old sensor from the console's Sensors & Agents page.

Do not delete the certificate files by hand to "force" a re-registration: the
sensor would try to register with a key that has already been used, and the
platform rejects it.

### The sensor cannot connect after a restart

Check, in the service log:

1. that the certificate files exist under `<dataPath>/certs/`;
2. that the configuration has `security.clientCertPath` set;
3. that `client.key` is `0600` and owned by the service account (Linux, macOS);
4. that this host still reaches your platform's URL.

If the files are missing or damaged, register again with a new key as above.

### "Registration was REJECTED by the control plane"

The key in the configuration was already redeemed, has expired, or is invalid.
Create a new key in the console and run the installer again with it. The
installer stops and disables the service when the platform rejects a key, so it
does not retry a key that can never work.

## Best practices

1. Do not edit the certificate files by hand.
2. Do not copy certificates between sensors: each sensor has its own identity.
3. Protect the private key; it authenticates the sensor.
4. Upgrade by running the new release's installer with no key: that keeps the
   certificate.

## For developers

The configuration's `security` block maps to `config.SecurityConfig` in
`internal/sensor/config/config.go`, which holds both the PEM data (loaded from
the files) and the file paths. `config.LoadFromFile` loads the certificates from
the paths; `config.SaveCertificatesToFiles` writes them with the permissions
above after registration or renewal and records the paths.
