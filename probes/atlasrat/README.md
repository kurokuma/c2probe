# AtlasRAT loader probe

`loader-sfuck.yaml` は旧型ローダーのチェックイン `53 46 75 63 6b 00 00 00`
を raw TCP で送信し、応答の先頭 7174 バイトだけ読み取ります。
先頭の x64 命令列 `48 89 5c 24 10` と、オフセット `0x1c04` の `MZ`
の両方が一致した場合、既知の AtlasRAT ローダー互換応答として `probable` を返します。
confidence 0.65 は経験的精度を測定した値ではなく、保守的な設定値です。

根拠は [Netresec の記事](https://www.netresec.com/?page=Blog&month=2026-10&post=Detecting-AtlasRAT-C2)
および [HexaStrike の解析](https://hexastrike.com/resources/blog/threat-intelligence/trust-the-tunnel-get-the-trojan-silver-fox-delivers-atlas-rat-via-weaponized-vpn-installers/)
です。後者の解析対象では、チェックイン後に 386380 バイトの未暗号化シェルコードが
返り、その内部に DLL が配置されています。本 probe はその先頭部分を受信しますが、
受信内容の実行、全体の取得、後続コマンドの送信は行いません。

この命令列と `MZ` は AtlasRAT 固有ではなく、配置も解析されたサンプルに依存します。
新型 `BFuck`、XOR/ChaCha20/TLS のバックドア通信は対象外です。
不一致、切断、タイムアウトから AtlasRAT の不在を判断することはできません。
実 C2 や実ペイロードでの検証は未実施です。ローカルテストは合成応答による
送信内容と照合条件の検証であり、実環境の検出精度を示すものではありません。

既存スキャンコマンドへ `--probe-dir probes/atlasrat` または
`--probe probes/atlasrat/loader-sfuck.yaml` を追加して使用できます。
ポートを固定していないため、スキャン対象の open port に適用されます。
