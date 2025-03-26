insmod rcone.ko
nft add rule ip nat PREROUTING iifname "tailscale0" rcone
nft add rule ip nat POSTROUTING oifname "tailscale0" rcone
nft add rule ip6 nat PREROUTING iifname "tailscale0" rcone
nft add rule ip6 nat POSTROUTING oifname "tailscale0" rcone
