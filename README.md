# NETIP Firewall
[![CI Status](https://github.com/oxmix/netip-firewall/workflows/Build%20and%20publish/badge.svg)](https://github.com/oxmix/netip-firewall/actions/workflows/hub-docker.yaml)

Open component `netip-firewall` for [oxmix.net](https://oxmix.net)
```shell
docker run -d --name netip.firewall --restart always \
  --cap-add=NET_ADMIN --network=host \
  -e HANDSHAKE_KEY=****** \
oxmix/netip-firewall:1
```
