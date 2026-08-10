# json_exporter for AAP Gateway Status

Deploy **json_exporter** on the **AAP Gateway VM** so Prometheus can scrape Gateway, Controller, Hub, EDA, and Redis status from `/api/gateway/v1/status/` without the Grafana Infinity plugin.

```
Prometheus  -->  http://<gateway_host>:7979/probe  -->  json_exporter
                                                              |
                                                              v
                                                   https://localhost/api/gateway/v1/status/
                                                              |
                                                              v
                                                         AAP Gateway
```

## What you get

The Gateway status API looks like this (services is a **list**, not a map):

```json
{
  "status": "good",
  "services": [
    { "service_name": "controller", "status": "good" },
    { "service_name": "hub", "status": "good" },
    { "service_name": "eda", "status": "good" },
    {
      "service_name": "redis",
      "status": "good",
      "response": { "status": "good", "mode": "standalone", "ping": true }
    }
  ]
}
```

json_exporter converts that into Prometheus metrics:

```
aap_gateway_status_up{status="good"} 1
aap_controller_status_up{status="good"} 1
aap_hub_status_up{status="good"} 1
aap_eda_status_up{status="good"} 1
aap_redis_info_up{mode="standalone",status="good"} 1
```

Metric names end with `_up` because the config uses `values.up: 1`.

Use these metrics with the dashboard:

`common/base/dashboards/grafana-aap-health-containerized-json-exporter-dashboard.json`

## Prerequisites

- AAP 2.5/2.6 containerized Gateway VM (RHEL)
- An AAP OAuth2 token with at least **System Auditor** / `read` scope
- Outbound HTTPS from json_exporter to the local Gateway API (`localhost`)
- Inbound TCP **7979** from the Prometheus host to the Gateway VM

## 1. Install json_exporter on the Gateway VM

```bash
# On the Gateway VM — check GitHub for the latest release version
curl -LO https://github.com/prometheus-community/json_exporter/releases/download/v0.6.0/json_exporter-0.6.0.linux-amd64.tar.gz
tar xzf json_exporter-0.6.0.linux-amd64.tar.gz
sudo cp json_exporter-0.6.0.linux-amd64/json_exporter /usr/local/bin/
sudo chmod +x /usr/local/bin/json_exporter
```

## 2. Place config and token

```bash
sudo mkdir -p /etc/json_exporter
sudo cp aap-gateway-status.yml /etc/json_exporter/config.yml

# Same AAP OAuth2 token used for Controller metrics scrape
echo "<AAP_TOKEN>" | sudo tee /etc/json_exporter/aap-token
sudo chmod 600 /etc/json_exporter/aap-token
```

## 3. Create systemd unit

```ini
# /etc/systemd/system/json_exporter.service
[Unit]
Description=Prometheus JSON Exporter for AAP Gateway status
After=network-online.target

[Service]
ExecStart=/usr/local/bin/json_exporter --config.file=/etc/json_exporter/config.yml
User=json_exporter
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /sbin/nologin json_exporter
sudo chown -R json_exporter: /etc/json_exporter
sudo systemctl daemon-reload
sudo systemctl enable --now json_exporter
sudo systemctl status json_exporter
```

## 4. Open firewall port 7979

```bash
sudo firewall-cmd --permanent --add-port=7979/tcp
sudo firewall-cmd --reload
```

## 5. Verify on the Gateway VM

```bash
curl "http://localhost:7979/probe?module=aap_gateway&target=https://localhost/api/gateway/v1/status/"
```

Expected output includes lines such as:

```
aap_gateway_status_up{status="good"} 1
aap_controller_status_up{status="good"} 1
aap_redis_info_up{mode="standalone",status="good"} 1
```

Hub and EDA lines appear only when those components are installed (`allow_missing_key: true` in the config).

---

## Endpoint to provide to the Prometheus team

Give the Prometheus team this scrape target (replace `<gateway_host>` with the Gateway VM hostname or IP):

```
http://<gateway_host>:7979/probe?module=aap_gateway&target=https://localhost/api/gateway/v1/status/
```

Notes:

- Prometheus scrapes **json_exporter on port 7979**, not the Gateway API directly.
- The `target=` query parameter tells json_exporter which URL to fetch. Because json_exporter runs on the Gateway VM, that URL is `https://localhost/api/gateway/v1/status/`.
- Authentication to the Gateway API is handled by json_exporter via `/etc/json_exporter/aap-token`. Prometheus does **not** need the AAP Bearer token for this scrape job.

### Example `prometheus.yml` scrape job (for the Prometheus team)

```yaml
- job_name: aap-gateway-status
  metrics_path: /probe
  params:
    module: [aap_gateway]
  static_configs:
    - targets:
        - https://localhost/api/gateway/v1/status/
  relabel_configs:
    - source_labels: [__address__]
      target_label: __param_target
    - source_labels: [__param_target]
      target_label: instance
    - target_label: __address__
      replacement: <gateway_host>:7979
  scrape_interval: 30s
```

This is the standard multi-target exporter pattern (same idea as blackbox_exporter).

## Troubleshooting

| Symptom | Check |
|---------|--------|
| `curl` to `:7979/probe` fails | `systemctl status json_exporter`, firewall for 7979 |
| Probe returns HTTP 401/403 | Token in `/etc/json_exporter/aap-token`, token scope `read` |
| Probe returns TLS errors | `tls_config.insecure_skip_verify` in `config.yml`, or install a trusted CA |
| Missing Hub/EDA metrics | Expected when those components are not installed |
| Grafana panels show N/A | Confirm Prometheus is scraping the job and metrics exist in Prometheus UI |

## Related files

| File | Purpose |
|------|---------|
| [aap-gateway-status.yml](aap-gateway-status.yml) | json_exporter module config |
| [../common/base/dashboards/grafana-aap-health-containerized-json-exporter-dashboard.json](../common/base/dashboards/grafana-aap-health-containerized-json-exporter-dashboard.json) | Grafana dashboard that queries these metrics |
