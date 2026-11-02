# PureRAT / PureHVNC

2026-11-02に [upstream de40d143](https://github.com/proshiba/AI-security-analysis/commit/de40d143f8d213126ac0b337c0ee0ab038ae0322)
の `purerat-c2.nse` / `purerat-direct-tls.nse` と照合しました。
証明書一致だけでは family 固有の通信や期待 TLS version を証明できないため、
一致しても `confirmed` にしません。不一致は family C2 の不在を意味しません。

| YAML | 動作・判定 |
|---|---|
| `direct-tls-d025.yaml` | `45.192.211.77:56001` だけで TLS 接続し、固定証明書 SHA-256 を照合。`probable` / 0.75、不一致 0.0。application data は送信しない |
| `prelude-tls-cert.yaml` | review 済みの `tirakian.com` の numeric IP と ports 56001/56002/56003 だけで `04000000` を送信し同じ stream を TLS 化。e554 の固定証明書一致は `probable` / 0.60、不一致 0.0 |
| `prelude-tls-observe.yaml` | 同じ限定 scope の任意観測。TLS 成立は `unclassified` / `observation` / 0.35。family 判定をしない |

e554 の静的証拠で endpoint と証明書は確認されていますが、当該 build の wire prelude は
未検証です。4-byte prelude は旧世代との互換性の仮説として扱います。
両 prelude YAML は、次の明示パラメータがないと directory 読み込み時に skip され、
ファイル直接指定では起動エラーになります。

```text
--probe-param purerat.tirakian_ip=<独立に確認したtirakian.comのIP>
--probe-param purerat.acknowledge_profile=purerat-e554-tirakian-legacy-prelude
```

旧 `purerat.expected_cert` は使用しません。期待証明書は e554 の
`67260a713ab105197098882f6d126f89fe4f48df8013f8bba1d2c9307b17410b` に固定しました。
`purerat.tirakian_ip` は domain に現在対応すると別途確認した単一 IP を指定してください。
c2probe は numeric IP scanner のため、NSE の targetname gate を自動検証できません。
この指定を hostname のレビューに代わる operator pin とし、acknowledgement は3 port
全体を対象とするグループ値です。upstream の port ごとの profile ID とは表現が異なります。
一致候補も出力するには `--output-mode detected` を使用してください。
directory 指定では2本の prelude probe がそれぞれ接続するため、通常は目的の1本を
`--probe` で指定してください。

rustls backend は TLS 1.2/1.3 です。direct profile の期待 TLS 1.0 は再現できず、
TLS 1.0 専用 server には接続できません。旧 prelude の期待 TLS 1.2 も、この構成では
TLS 1.3 を排除していないため `tls_version_enforced: false` としています。

テストは一時的な自己署名証明書を使い、テストコピーの pin のみ差し替えた loopback mock
です。実 C2、検体実行、実 payload での検証は行っていません。
