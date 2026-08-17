# upstream NSE全件対応表

対象は2026-08-17に取得した
[`analysis-framework/nmap/scripts`](https://github.com/proshiba/AI-security-analysis/tree/main/analysis-framework/nmap/scripts)
の12ファイルです。NSEは任意Luaなので機械的な逐語変換は行わず、通信、境界値、判定確度、
scopeをレビューしてc2probeの制限付きDSLまたは既存native機能へ対応付けました。

## 対応結果

| upstream NSE | c2probe実装 | 判定 | 備考 |
|---|---|---|---|
| `agenttesla-ftp-c2.nse` | `probes/agenttesla/ftp-banner.yaml` | observation | 匿名の`220` bannerのみ。資格情報を伴う任意FTP loginは意図的に実装しない |
| `c2-dns-observe.nse` | target list作成前のDNS解決 | native observation | NSE自体もC2判定を行わない。c2probeはIP/CIDR scannerなので、解決したIPを`-t`/`-i`へ渡す |
| `c2-transport-observe.nse` | `probes/observations/*.yaml`とdiscovery | observation | server-first、TLS certificate、HTTP、HTTPSは4 YAML。tcp-openは`--scan-mode discovery --output-mode open` |
| `darkcomet-c2.nse` | `probes/darkcomet/{raw,ascii-hex}.yaml` | confirmed | reviewed RC4鍵を`darkcomet.key_base64`で明示する |
| `dotnet-rat-c2.nse` | `probes/dotnet-rat/{asyncrat,venomrat}.yaml` | confirmed | byte-exact Ping、length frame、gzip、MessagePack key/valueを検証 |
| `purerat-c2.nse` | `probes/purerat/prelude-tls-*.yaml` | observation / confirmed | `04000000`後に同一streamをTLS化。証明書一致ruleは期待SHA-256が必須 |
| `purerat-direct-tls.nse` | `probes/purerat/direct-tls-d025.yaml` | confirmed | `45.192.211.77:56001`と証明書SHA-256をscopeへ固定 |
| `redline-c2.nse` | `probes/redline/checkconnect-production.yaml` | confirmed | 固定endpointへSHA-256一致の357-byte request。応答XMLはcanonical namespace表現の4階層boolean envelope |
| `stealer-http-c2.nse` | `probes/stealer-http/*.yaml` | confirmed / probable | StealCはRC4 tokenまで確認。Lumma/Remusは形状だけなのでprobable |
| `stealer-route-c2.nse` | `probes/stealer-route/*.yaml` | probable | production 5 profile。明示IP pin、固定Host/path、HEAD、negative controlを保持 |
| `valleyrat-c2.nse` | `probes/valleyrat/{winos,vvas,n520}.yaml` | confirmed | strict converterとfixture比較を維持 |
| `xloader-c2.nse` | discovery/open result | native observation | upstreamもapplication requestやC2判定を行わないため`--scan-mode discovery --output-mode open`が同等 |

DNS observationとXLoader tcp-open observationを「C2判定YAML」に見せかけると、任意の名前解決や
open portをC2として誤分類します。この2本はapplication probeを生成せず、native機能との対応を
明示するのが意味的に同等です。従って、12/12に実行経路があり、application通信を持つ10/12は
YAMLまたはYAML群へ変換されています。

## 必須パラメータ

| probe family | `--probe-param` | 制約・意味 |
|---|---|---|
| DarkComet | `darkcomet.key_base64=...` | reviewed RC4 key。結果やlogへ値を出さない |
| PureRAT cert match | `purerat.expected_cert=<64 hex>` | leaf certificate SHA-256 |
| StealC | `stealer.build=...`, `stealer.key_base64=...` | reviewed build IDとRC4 key |
| Lumma | `stealer.uid=<32-64 hex>` | synthetic UID。`stealer.cid`は任意 |
| Remus | `stealer.tag=<32 hex>`, `stealer.exp=<decimal>` | synthetic registration fields |
| FormBook | `formbook.expected_ip=<IP>` | domainを外部で解決・検証したnumeric IP pin |
| Vidar | `vidar.expected_ip=<IP>` | reviewed numeric IP pin |
| AMOS | `amos.<profile>_expected_ip=<IP>` | 各domainの外部検証済みnumeric IP pin |

パラメータ必須YAMLを`--probe-dir`で読み、値がない場合、そのYAMLだけを警告付きでskipします。
`--probe`でファイルを直接指定した場合は、設定漏れとして起動を失敗させます。

## upstream snapshot

取得日: 2026-08-17。SHA-256は変換対象を固定し、upstream変更を黙って同等扱いしないための値です。

| file | SHA-256 |
|---|---|
| `agenttesla-ftp-c2.nse` | `fff1497f06af248b0db7ecf8e8ebda9c39e209d7389904385b4621f147891052` |
| `c2-dns-observe.nse` | `8d6769949e1a2884a17d39452506ae54ce2e2db4c53899374b3dcd003597fadd` |
| `c2-transport-observe.nse` | `18e6470f51bd93722fdc71754b7096cddea51f723fff56d62b89441064065585` |
| `darkcomet-c2.nse` | `700cc85fbe5cfc80cfce7c6993970ae353d5aecca82fe4bfe92b08ce624f0cc3` |
| `dotnet-rat-c2.nse` | `35d408ababcb4fc28fcd819e185ccbe3fb71b0e7d869451325126b93aeb2382c` |
| `purerat-c2.nse` | `40f28942adc705c67d4ae214f970e4e50651c8b74548087c3ba2925652d2fecf` |
| `purerat-direct-tls.nse` | `d895aaffe53ce8362d3cfb1aaf09f1876cde03332b8709b03b76380886627954` |
| `redline-c2.nse` | `9f9c4c8c4137f04c94d7fb25b4fd0a1682f31a4f1213cc01e5d33d047b4cc7dc` |
| `stealer-http-c2.nse` | `2a98f92abfb459c03517f264829301c3ada2efb13010e5c5d751a21d0a3002c0` |
| `stealer-route-c2.nse` | `32b4e4d99878b51d801c8e7c0d105d522b3d2d437b78ba4e6501157ae71514e5` |
| `valleyrat-c2.nse` | `708768eec241fd39013b5787af56a0ee20351e1399d65345c75862afb23e5b0f` |
| `xloader-c2.nse` | `d3836e1c74d5f9267adb70e4a426032ea0be1d317fc5fce9a601a0c7028ce3e9` |

## 既知の表現差

- RedLineはNSEのnamespace-aware XML parserではなく、canonical `s`/default namespace表現だけを許す保守的regexです。
- HTTP parserはchunked responseと重複headerを拒否します。曖昧なframingを受理しません。
- transport observationのHTTP path/Host overrideはYAMLでは`/`とtarget IPへ固定しています。
  任意のreview済み経路を調べる場合はYAMLを複製してpath/Hostを明示します。
- Route profileのloopback test vectorsはproduction scanner ruleに含めず、local test用途としています。
- AgentTeslaの認証optionは、第三者credential送信を避けるためbanner observationへ限定しています。
- c2probeのrustls backendはTLS 1.2/1.3です。PureRAT direct profileに記録された期待値はTLS 1.0ですが、
  upstream NSE自身もTLS 1.0を強制していません。対象がTLS 1.0だけを許す場合、現行backendでは
  handshakeできず`tls_error`になります。証明書ruleの静的変換完了とlegacy TLS runtime受入は別です。
- ValleyRAT Winosの詳細差分は`docs/NSE_CONVERSION.md`を参照してください。

これらは偽陽性や能動操作を増やす方向ではなく、原則として保守的部分集合です。実サーバとの
Nmap differential testは、明示的に許可されたLinux環境で別途行う必要があります。
