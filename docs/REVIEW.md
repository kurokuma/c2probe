# Phase 0–5およびupstream NSE registry 成果物レビュー

レビュー日: 2026-08-17

## 結論

Phase 0–5で定義した実装項目はソース、CLI、probe、README、仕様、build packageへ反映されている。
前回未完了だったPACK、CONCAT、per-probe concurrency、運用metricsも実装した。
Windowsで実行可能な品質ゲートとLinux向け型・lint検査は合格した。

2026-08-17にはupstream 12 NSEを再inventoryし、application通信を24 YAMLへ展開、または
native discovery/target preprocessingへ意味的に対応付けた。DSL/IR/Executorへbounded HTTP、
STARTTLS、certificate hash、RC4/Base64/gzip/MessagePack、scope、parameter、確度区分を追加した。

Linux Raw SYNの実通信と性能値は、このWindows環境では実証していない。したがって
250k pps以上の性能、packet loss、実NIC上の応答回収率はリリース受入の残項目である。

## 確認結果

| 対象 | 結果 |
|---|---|
| rustfmt | 合格 |
| Windows全target Clippy (`-D warnings`) | 合格 |
| unit test | 43/43 合格（Windows） |
| Mock/統合test | 21/21 合格 |
| Linux x86_64、TLS無効の型検査 | 合格 |
| Linux x86_64固有コードのClippy | 合格 |
| Linux x86_64、TLS有効のWindows cross build | `x86_64-linux-gnu-gcc`未導入のため環境block |
| Windows release build | 合格（今回差分で再実行） |
| packaged executable `--help` | 合格（`c2probe.exe`、`nse2yaml.exe`） |
| ZIP内容とSHA-256 | 合格。24 YAML、公開文書4本、README、specを確認 |
| Linux Raw SYN実通信 | 未検証 |
| Linux CPU affinity実動作 | 未検証 |
| 性能・loss benchmark | 未検証 |

## コードレビューで確認した境界

- `sendmmsg`へ渡すpacket、destination、`iovec`の格納先はsyscall中に再配置されない。
- partial sendは未送信の`mmsghdr`から再開し、0件送信はエラーとする。
- raw socketはRAIIでcloseし、`IP_HDRINCL`設定失敗時もfdをcloseする。
- SYN/ACKはworker固有source portとstateless cookieのACK値で対応付ける。
- CPU IDは`CPU_SETSIZE`と現在のcpusetをruntime生成前に検証する。
- process shardingは同一`IP:PORT`を同じworkerへ割り当てる。
- PACK/CONCATで生成したWinos request全15 byteがreference frameと一致する。
- global、host別、probe別Semaphoreが独立して接続数を制限する。
- targets、SYN/probe rate、active connections、queue depthをsummaryで出力する。
- worker stdoutはbounded channel経由で親が単一JSONLへ集約する。
- DSLは任意コード、process、filesystem操作を提供せず、受信/YAMLサイズ上限を維持する。

## レビュー中に修正した事項

1. probe重複排除キーでprobe名をjobごとに`String`化していたため、`Arc<str>`共有へ変更した。
2. CPU affinity失敗をthread開始後の警告だけにしないよう、現在のLinux cpusetを事前検証した。
3. 性能資料をbuild packageへ含めるため、Linux/Windows両build scriptへ`docs`コピーを追加した。
4. Linux固有コードをcross-target Clippyの対象にし、warningを解消した。
5. 利用者要件に合わせて`--authorized`と`--dry-run`をCLI・実行経路から削除し、
   target/probe検証後に直ちにスキャンを開始する動作へ変更した。
6. Raw SYNの個別送信失敗を致命的エラーにせず、対象`IP:port`をログとmetricsへ記録して
   後続jobを継続するよう変更した。CLIログレベルとファイル追記も追加した。
7. 各出力レコードを即時flushし、定期・正常・異常終了時に`sync_data`するよう変更した。
   task errorは既存ResultQueueをdrainしてから返し、長時間scanの途中成果を保持する。
8. NSEを実行しないstrict `nse2yaml` converterを追加した。参照ValleyRAT NSEから3 ruleを
   生成し、既存YAMLとの構造比較と差分reportを自動testにした。
9. upstream directoryの12 NSEすべてへ明示的な対応を作成した。application protocolは24 YAML、
   DNS/tcp-openだけの観測はnative機能へ対応付け、偽のC2判定ruleを作らない。
10. parameter値の型・長さ、IP/port scopeをcompile時に検証し、directory読込時は不足ruleだけを
    skip、明示file指定時は起動失敗とした。鍵値はlog/resultへ出力しない。
11. `confirmed`、`probable`、`observation`を分離し、`--output-mode detected`を追加した。
12. packageへ内部`docs/FIXES.md`を混入させず、公開対象4文書だけをコピーするようbuild scriptを
    修正した。PowerShell parser検査は合格、Linux shell構文検査はWSL起動権限不足で未実施。
13. Winosのrequest reflectionを`reject_if`とbuffer間prefix比較で除外し、反射時はconfidence 0、
    `winos_request_reflected`、`request_reflected=true`としてconfirmedへ進めないよう修正した。

## Linuxリリース前の残作業

[PERFORMANCE.md](PERFORMANCE.md)の受入試験をLinux検証hostで実施し、kernel/NIC/CPU条件と
測定結果を保存すること。特にbatch size 1対64/128、single対multi-processの結果集合一致、
重複、pps、RSS、CPU、NIC drop、SYN/ACK回収率を確認する。

今回のレビューではworking tree差分と`git diff --check`を確認した。commit作成、署名、
実Linux endpointに対するNmap differential testは実施していない。
