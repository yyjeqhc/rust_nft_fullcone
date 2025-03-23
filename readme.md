本项目基于https://github.com/fullcone-nat-nftables进行修改。

基于[yyjeqhc/rust_xt_fullcone: 基于https://github.com/Chion82/netfilter-full-cone-nat的rust编写样例测试](https://github.com/yyjeqhc/rust_xt_fullcone)（基于xt框架）

和上面项目的区别就是，本项目需要编译文件夹中的libnftnl-1.2.8和nftables-v1.1.1，此外，本项目基于nft框架

编译的方式，请参考[yyjeqhc/nft_fullcone: This project is based on nft_fullcone, sourced from https://github.com/fullcone-nat-nftables.](https://github.com/yyjeqhc/nft_fullcone)

测试环境也和上面的类似，不做赘述。

使用：

```shell
nft add rule ip nat PREROUTING iifname "tailscale0" fullcone
nft add rule ip nat POSTROUTING oifname "tailscale0" fullcone

nft add rule ip nat PREROUTING iifname "tailscale0" rcone
nft add rule ip nat POSTROUTING oifname "tailscale0" rcone

nft add rule ip nat PREROUTING iifname "tailscale0" prcone
nft add rule ip nat POSTROUTING oifname "tailscale0" prcone

分别是全锥型，源地址限制型，源地址端口限制型。

仅实验目的，没有支持其他功能。
此外，使用此模块可能会导致系统崩溃，请谨慎使用。
```

