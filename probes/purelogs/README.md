# PureLogs

`https-ping.yaml` は [upstream de40d143 の purelogs-c2.nse](https://github.com/proshiba/AI-security-analysis/blob/de40d143f8d213126ac0b337c0ee0ab038ae0322/analysis-framework/nmap/scripts/purelogs-c2.nse)
を元に追加しました。対象は review 済み `193.26.115.118:8443` のみです。

1. TLS leaf 証明書 SHA-256 が `9e254cab8c68944cea18a3ac5523fe491eb14f9447b352dca33729b64eaeeac3`
   と一致するか確認。不一致時は HTTP request を送信しません。
2. `Host: logs.uvexio.com` の匿名 `GET /ping` を1回だけ送信します。本文はなく、
   request は256 byte以下、response は header 最大1022 byte＋body 最大2 byteです。
3. HTTP 200、`Content-Length: 2`、本文が厳密に `OK` のときだけ `probable` / 0.70。
   redirect、重複 header、転送・内容 encoding、過大・不完全な応答は受理しません。

利用時には固定 profile の明示指定が必要です。

```text
--probe-dir probes/purelogs
--probe-param purelogs.acknowledge_profile=purelogs-0f2abaab-logs-uvexio-8443-ping-v1
--output-mode detected
```

指定なしでは directory 読み込み時に skip、ファイル直接指定では起動エラー、
異なる acknowledgement 値では compile エラーになります。DSL parameter に
`allowed_values` を追加し、ネットワーク接続前にこの固定値を検証します。
profile ID・IP・Host・証明書は YAML に固定し、任意 endpoint 向けの一般化はしていません。

upstream の body SHA-256 条件は、固定2 byte `OK` の完全一致で同等に表現します。
response 本文や raw response は結果へ出しません。期待 TLS 1.2 だけの強制はせず、
`tls_version_enforced: false` を出力します。`http_aes_v5` は family-level の分類で、
この sample の version 確定を意味しません。legacy socket / 3DES codec は未対応です。
証明書不一致や応答不一致は PureLogs の不在を証明しません。

検証はテストコピーの証明書 pin だけ差し替えた合成 loopback mock です。
実 C2 には接続せず、検体や payload の取得・実行も行っていません。
