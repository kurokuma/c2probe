# 性能設計とLinux検証手順

## 実装済みの最適化

- Linux Raw SYN送信は`sendmmsg(2)`を使い、`--syn-batch-size`（既定64）件までを
  1 syscallで送信する。
- パケット本体、`iovec`、`mmsghdr`の`Vec`は起動時に容量を確保し、バッチ間で再利用する。
- 送信元IP解決用UDP socketも再利用する。
- Probe IRは起動時に一度だけcompileし、実行時は`Arc`で共有する。重複排除キーも
  probe名の文字列を再確保せず`Arc<str>`を共有する。
- bounded channelとSemaphoreにより、discovery、probe、output間にbackpressureをかける。
- global、host別、probe別の3段階Semaphoreで接続数を制限する。
- `--cpu-affinity`でLinux CPU IDを指定できる。複数processではCPU集合をstride分割し、
  各workerのTokio thread、Raw SYN sender、receiverをその集合へ固定する。
- `--processes`はtargetのport列を重複なく分割し、rate・thread・concurrencyの合計値も
  workerへ分配する。
- `sendmmsg`の個別destination失敗は`IP:port`を警告ログへ記録してskipし、残りを継続する。
- JSONL/CSVは各レコード後にflushし、`--flush-interval`ごとに`sync_data`する。task error時も
  完了済みResultQueueをdrainして同期してから終了する。

## 推奨する段階的な調整

最初は許可された小さい検証ネットワークで、単一process・低rateから開始する。

```bash
sudo setcap cap_net_raw=eip ./c2probe
./c2probe -i targets.txt -p 1-10000 --scan-mode discovery \
  --syn-rate 10000 --max-rate 10000 --syn-batch-size 64 \
  --output-mode open --output open.jsonl
```

CPUとNICに余裕がある場合だけrate、batch、processを一つずつ増やす。

```bash
./c2probe -i targets.txt -p all --probe-dir probes/valleyrat \
  --processes 4 --threads 16 --cpu-affinity 0-15 \
  --syn-rate 250000 --max-rate 250000 --syn-batch-size 128 \
  --probe-concurrency 10000 --per-host-concurrency 64 \
  --per-probe-concurrency 1024 \
  --output result.jsonl
```

batchを大きくするとsyscall数は減るが、短いscanのburstと待ち時間は増える。
一般には64または128から測定し、packet lossとrateの安定性を見て変更する。

## SYN送受信のカーネル設定

Raw SYNは送信元ポートにsocketをbindしない。したがってSYN/ACKを受け取ったカーネルは、
自身が知らない接続としてRSTを返す。これはSYN scanでは通常の挙動だが、対象側から見ると
接続が即座にresetされるため、送出を抑止したい場合は明示的にDROPする。

```bash
# scanner のsource portは ip_local_port_range の外から選ばれる
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

送信元ポートは`/proc/sys/net/ipv4/ip_local_port_range`を読み、その範囲外から選択する。
これによりローカルの通常通信と同じポートが割り当てられ、応答の対応付けが汚染されることを
避ける。SYN/ACKの照合cookieはプロセス起動ごとに`/dev/urandom`から生成した鍵で計算するため、
固定値ではなく、off-pathからの偽装SYN/ACKでopen portを注入されにくい。

sequence numberの下位8 bitには4 ms刻みの送信時刻を埋め込んでおり、`syn_rtt_ms`はここから
算出する。1周は1024 msなので、`--syn-timeout`が1000 msを超える設定ではRTTを出力しない。

## rate制御の粒度

rate limiterは1バッチ送信ごとにsleepするため、瞬間的な送出単位は`--syn-batch-size`分に
なる。またjob供給が滞った時間は送信クレジットとして蓄積されない（蓄積すると、待機後に
`--max-rate`を超えるburstが発生するため）。したがって実測ppsは平均値として`--syn-rate`に
収束し、瞬間値はbatch sizeぶん上振れする。

## Linux受入試験

次を同じhost・同じtarget setで記録する。

1. `cargo test --locked --all-targets`とClippyが成功すること。
2. capability付与後、許可済みMock/検証hostのopen portをdiscoveryできること。
3. `--syn-batch-size 1`と64/128で結果集合が一致すること。
4. 単一processと複数processで結果集合が一致し、同一`IP:PORT`の重複がないこと。
5. `/usr/bin/time -v`、`pidstat -p ALL 1`、NIC counter、送信/応答件数を保存すること。
6. 目標rateごとに送信pps、SYN/ACK回収率、CPU、RSS、drop、完了時間を比較すること。
7. 到達不能レンジを含むtarget listでscanが中断せず、summaryの`skipped`に計上されること。
8. closed portへのscanで`closed`が計上され、`open`と区別されること。
9. `syn_rtt_ms`が既知RTT（`tc qdisc`等で付与した遅延）とtick粒度内で一致すること。
10. scan中のCtrl+Cで出力JSONLが最終行まで完結し、summaryが表示されること。
11. 拒否されるdestinationを混在させ、`send_errors`/`skipped`が増えて後続targetを送信できること。
12. 結果生成後に意図的なtask errorを起こし、非0終了でも既存JSONLが完全な行として残ること。

検証結果にはkernel、CPU topology、NIC、offload設定、target数、port数、rate、batch、
process/thread/concurrencyを必ず併記する。Windowsでのクロス型検査は、Linux Raw socketの
実行、CPU affinity、実pps、packet lossを証明しない。

## 運用上の注意

- CLIは確認フラグを要求せず即時実行する。対象範囲と除外を運用手順で事前承認する。
- `--max-rate`を組織の安全上限として固定し、実行者が`--syn-rate`で超えられないようにする。
- CPU IDはLinuxのcpuset/cgroup内で利用可能な番号を指定する。無効なIDでは起動に失敗する。
- 複数processの集約出力は現在JSONLのみ。workerのstderr順序は保証しない。
- Raw SYNはIPv4のみ。IPv6はprobe modeで既知のsocket targetへ接続する。
