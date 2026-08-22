# 敵対的レビュー 修正事項

レビュー日: 2026-08-15
修正日: 2026-08-15
対象: `spec.md` / `README.md` と `src/`、`probes/`、`tests/` の実装全体
レビュー時のビルド状態: `cargo test --locked --all-targets` 20件合格（unit 14 + 統合 6）

追記: 後続の利用者要件により`--authorized`と`--dry-run`は削除した。本書内の
`--dry-run`コマンドとF-09の記述は、削除前に行ったレビューの履歴として残している。
現在のCLIではtarget/probe検証後にスキャンを直ちに開始する。

## 対応状況

F-26を除く25件を修正した。F-26は依存crateの差し替えであり、別途計画する。

修正後の検証:

| 項目 | 結果 |
|---|---|
| `cargo fmt --all -- --check` | 合格 |
| `cargo clippy --locked --all-targets -- -D warnings` | 合格 |
| `cargo test --locked --all-targets` | 57件合格（unit 43 + 統合 14） |
| Linux target（`--no-default-features --bins --lib`）のClippy | 合格 |
| 修正前に再現していた6件のCLI挙動 | 再実行して解消を確認 |

Linux実機でのRaw SYN実通信、CPU affinity、性能・packet loss、Nmap NSEとの
Differential Testは引き続き受入試験の対象で、ここでは検証していない。特にF-03、F-04、
F-14、F-15はLinux実機での確認手順を[PERFORMANCE.md](PERFORMANCE.md)の受入試験へ追加した。

以下は認識済み残課題として除外している。

- Linux実機でのRaw SYN・CPU affinity動作検証
- 250k pps、packet lossなどの性能試験
- Nmap NSEとのDifferential Test
- 将来拡張扱いのResume、UDP、Probe Registry、外部enrichment
- Phase対象外のDSL拡張命令（RECV_UNTIL、MATCH_REGEXなど）

「実証」と記載した項目は、このレビュー中に実際にバイナリを実行して再現を確認したもの。
「静的確認」はコードおよび依存crateのソース読解による。

---

## サマリ

| ID | 重大度 | 概要 | 確認方法 | 状態 |
|---|---|---|---|---|
| F-01 | 高 | 既定でwarn/infoログが全て破棄される | 実証 | 修正済 |
| F-02 | 高 | IPv6 targetがfull/discoveryで無言のまま捨てられる | 実証 | 修正済 |
| F-03 | 高 | rate limiterが送信クレジットを蓄積し`--max-rate`を超えるburstを許す | 静的確認 | 修正済 |
| F-04 | 高 | 経路解決できない宛先1件でスキャン全体が異常終了 | 静的確認 | 修正済 |
| F-05 | 高 | job生成完了後はCtrl+Cが完全に無効化される（spec §37違反） | 静的確認 | 修正済 |
| F-06 | 高 | multi-process親がCtrl+Cで無flush終了し集約JSONLが壊れうる | 静的確認 | 修正済 |
| F-07 | 高 | `insecure_tls: false`のTLS probeは必ず失敗する | 静的確認 | 修正済 |
| F-08 | 中 | `--exclude`がprobeモードの`IP:PORT`に効かない | 実証 | 修正済 |
| F-09 | 中 | `--dry-run`の件数が実際と一致しない | 実証 | 修正済 |
| F-10 | 中 | compile時にbuffer長とoffsetの整合を検証しない | 実証 | 修正済 |
| F-11 | 中 | `bytes_eq`の空hexが常に真になる | 実証 | 修正済 |
| F-12 | 中 | match stepが複数あるとconfidence/statusが不整合になる | 静的確認 | 修正済 |
| F-13 | 中 | schedulerのhost semaphoreとdedup setが解放されない | 静的確認 | 修正済 |
| F-14 | 中 | port_stateが常にopen、syn_rtt_msが常にnull | 静的確認 | 修正済 |
| F-15 | 中 | source portがephemeral範囲と衝突、cookie secretが固定値 | 静的確認 | 修正済 |
| F-16 | 低 | `-iL targets.txt`がspec記載どおり動かない | 実証 | 修正済 |
| F-17 | 低 | `--output-mode open`でもprobeを実行して結果を捨てる | 静的確認 | 修正済 |
| F-18 | 低 | error分類にspec §34の2種が欠落、TLS timeoutの分類が不正確 | 静的確認 | 修正済 |
| F-19 | 低 | 出力flushがBufWriter任せでstreamingにならない | 静的確認 | 修正済 |
| F-20 | 低 | metricsのラベルと実体が乖離、live statusが未実装 | 実証 | 修正済 |
| F-21 | 低 | `--probe-dir`の再帰が1階層のみ | 静的確認 | 修正済 |
| F-22 | 低 | probe実行時のメモリ上限がない | 静的確認 | 修正済 |
| F-23 | 低 | `pack`が値を無言で切り詰める | 静的確認 | 修正済 |
| F-24 | 低 | `bytes_eq`のoffset加算がオーバーフローしうる | 静的確認 | 修正済 |
| F-25 | 低 | 受信側がOpenPort送信失敗を無視して走り続ける | 静的確認 | 修正済 |
| F-26 | 情報 | `serde_yaml` 0.9はunmaintained | 静的確認 | 未対応（別計画） |

---

## 高

### F-01 既定設定でwarn/infoログが全て破棄される

**場所**: `src/main.rs:56-59`

`EnvFilter::from_default_env()` は `tracing-subscriber` 0.3.23 の実装で
`with_default_directive(LevelFilter::ERROR)` を使う。`RUST_LOG` 未設定時は
ERROR以上しか通らないため、本ツールの警告が1件も表示されない。

失われる情報:

- `src/discovery/linux.rs:172` IPv6 raw SYN未実装の警告（F-02の実害に直結）
- `src/discovery/linux.rs:53` 非root実行時の権限警告
- `src/main.rs:97` 1億port超スキャン時の確認警告
- `src/multiprocess.rs:41` worker起動情報

**実証**:

```text
$ c2probe ... --processes 2 ...        → worker起動ログなし
$ RUST_LOG=info c2probe ... --processes 2 ... → INFO starting worker processes ... が出る
```

**修正**: `EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy()`
に変更する。安全機構に関わる警告（権限、大規模スキャン、IPv6 skip）はログ経路に依存させず
`eprintln!`でも出す。

---

### F-02 IPv6 targetがfull/discoveryで無言のまま捨てられる

**場所**: `src/discovery/linux.rs:170-174`、`src/main.rs:149-169`

`add_job`はIPv6宛先を`tracing::warn!`してskipする。F-01によりこの警告は出ない。
結果として`--scan-mode full`にIPv6を渡すと、警告なし・結果0件・exit code 0で正常終了する。
「対応していない」ではなく「スキャンして何も見つからなかった」と誤読される。

**実証**: `-t 2001:db8::/126 -p 80 --dry-run` は `targets=4 scheduled=4` と表示する。
実行時にはこの4件が全て破棄される。

**修正**: `TargetSet`にIPv6ネットが含まれ、かつ`scan-mode`がfull/discoveryの場合は
`validate()`段階で明示的にエラーにする（`--scan-mode probe`を案内する）。
段階移行するなら、最低限skip件数をmetricsに計上し、起動時に一度だけstderrへ出す。

---

### F-03 rate limiterが送信クレジットを蓄積し`--max-rate`超のburstを許す

**場所**: `src/discovery/linux.rs:109`、`146-149`

```rust
let mut next = Instant::now();
...
next += Duration::from_secs_f64(sent as f64 / rate as f64);
if let Some(delay) = next.checked_duration_since(Instant::now()) { sleep(delay); }
```

`next`が現在時刻より遅れた場合に補正されない。job供給が滞る期間（scan開始直後、
巨大なtarget fileの読み込み待ち、Phase 2 backpressureからの回復直後）がT秒あると、
その後 `T × rate` packetsをsleepなしで連続送出できる。

`--max-rate`はspec §47の誤操作防止機構であり、平均レートだけでなく瞬間的な
送出量を抑える意図があるため、実効性が損なわれている。

**修正**: 送信前に `next = next.max(Instant::now());` を入れ、蓄積クレジットを
最大1バッチ分に制限する。あわせて`--syn-batch-size`が大きいときのburst幅
（batch_size / rate 秒分）をPERFORMANCE.mdに明記する。

---

### F-04 経路解決できない宛先1件でスキャン全体が異常終了

**場所**: `src/discovery/linux.rs:163-177`、`335-359`

`add_job` → `routes.source_for(dst)?` は `UdpSocket::connect` の失敗をそのまま
`run()`の戻り値へ伝播する。`ENETUNREACH`や`EACCES`（ローカルpolicyでのblock）が
1件混じるだけで、`syn_scan`がErrになり`main`の`scan.await??`でプロセスが終了する。
それまでに検出したopen portの後続probeも巻き添えで打ち切られる。

大量IPリストには到達不能なレンジが混入するのが常なので、実運用では高確率で踏む。

**修正**: 宛先単位でskipし、`route_unreachable`カウンタを加算してログに残す。
バッチ全体は継続させる。

---

### F-05 job生成完了後はCtrl+Cが完全に無効化される

**場所**: `src/main.rs:140-145`、`162-165`

`tokio::signal::ctrl_c()` をproducerループの`select!`内で毎周新規生成している。
tokioのドキュメント（`tokio-1.53.1/src/signal/ctrl_c.rs`）は次を明記している。

- future は「poll開始**後**に受信した」ctrl-cでのみ完了する
- 一度registerするとOS handlerはプロセス終了まで解除されない。
  Signalをdropしても「default platform behavior will NOT be reset」

この2点から、次の2つの不具合が生じる。

1. **job生成が終わった後、Ctrl+Cが一切効かない。** Phase 1のdrain（`scan.await`）、
   Phase 2の全probe実行、output flushの間、SIGINTはtokioに捕捉されるがlistenerが
   いないため破棄される。既定のプロセス終了動作も既に置き換えられているため、
   ユーザーは`kill`しない限り中断できない。長時間スキャンの運用上の問題であり、
   spec §37のgraceful shutdown要件を満たしていない。
2. **周回の隙間に届いたSIGINTを取りこぼす。** 前回のfutureをdropしてから次を生成する
   までの窓に来た信号は、どのlistenerにも配送されない。

**修正**: 起動直後に一度だけ `tokio::spawn(async { ctrl_c().await; token.cancel() })`
を行い、`CancellationToken`（または`watch::Sender<bool>`）をproducer、scheduler、
discovery senderへ共有する。schedulerは新規probe起動を止め、実行中probeを一定時間
待ってからResultQueueをflushする（spec §37の1〜6）。

---

### F-06 multi-process親がCtrl+Cで無flush終了し集約JSONLが壊れうる

**場所**: `src/multiprocess.rs:79-86`、`108-120`

親プロセスはsignalを一切扱わない。端末のCtrl+Cはforeground process group全体へ
届くため、親は既定動作で即死する。このとき`BufWriter`（既定8 KiB）の未flush分は
失われ、ファイル末尾がJSONL行の途中で切れる可能性がある。`kill_on_drop`のDrop実装も
シグナル終了では走らない。

spec §37の「JSONLファイルを壊さない」に反する。

**修正**: 親にもF-05のshutdown tokenを持たせ、SIGINT時は
（1）子へのSIGINT伝播を待つ、（2）`line_rx`を最後までdrain、（3）`flush()`、
（4）`child.wait()`、の順で終了する。

---

### F-07 `insecure_tls: false`のTLS probeは必ず失敗する

**場所**: `src/probe/transport.rs:87-91`

```rust
ClientConfig::builder()
    .with_root_certificates(rustls::RootCertStore::empty())
```

ルート証明書0件のstoreでは、あらゆるサーバ証明書が`UnknownIssuer`で拒否される。
つまり`transport: {type: tls}`かつ`insecure_tls`未指定（既定false）のprobeは、
相手が正規のC2であってもなくても100% `tls_error`になる。

同梱の`n520.yaml`は`insecure_tls: true`なので現状のテストでは露呈しない。しかし
DSL作者が「証明書検証を有効にする」という安全側の選択をすると機能が死ぬ、という
逆転した挙動になっている。

**修正**: いずれかを選ぶ。

- `webpki-roots` または `rustls-native-certs` を導入して実際の検証を行う
- 検証を提供しないと決めるなら、`insecure_tls: false` + `type: tls` を
  **compile時に拒否**し、「このバージョンのTLS transportは`insecure_tls: true`が必須」
  と理由を出す（fingerprint用途では証明書検証は本来不要なので、こちらが妥当）

いずれの場合もREADMEの「Probe DSLの安全境界」に扱いを明記する。

---

## 中

### F-08 `--exclude`がprobeモードの`IP:PORT`に効かない

**場所**: `src/target/mod.rs:56-65`、`67-87`

`iter_ips()`はexcludesでフィルタするが、`socket_targets`/`socket_targets_shard`が
chainする`self.sockets`（probeモードの`IP:PORT`）はフィルタを通らない。

**実証**:

```text
$ c2probe -t 127.0.0.1:48122 --scan-mode probe --exclude 127.0.0.1 --dry-run
targets=1 ...      ← 除外されていない
```

spec §47の誤操作防止機構が、probeモードでだけ無効になっている。除外リストは
「絶対に触れてはいけない資産」を指定する用途なので影響が大きい。

**修正**: `sockets`のiterationにも`!self.excludes.iter().any(|n| n.contains(&ip))`を適用する。
除外にport指定（`IP:PORT`形式）を許すかどうかも決めてREADMEに書く。

---

### F-09 `--dry-run`の件数が実際と一致しない

**場所**: `src/target/mod.rs:89-95`、`src/main.rs:66`、`80-95`

`ip_count()`は（1）excludesを差し引かない、（2）`IP:PORT`のsocket targetを
「IP 1件」として数える。`main`は`total = ip_count × ports.len()`で総job数を出す。

**実証**:

```text
$ c2probe -t 127.0.0.0/30 -p 80 --exclude 127.0.0.0/30 --dry-run
targets=2 scheduled=2        ← 実際にスキャンされるのは0件

$ c2probe -t 127.0.0.1:48122 --scan-mode probe --dry-run
targets=1 ports_per_target=65535 scheduled=65535   ← 実際は1接続
```

`--dry-run`はspec §47で「実行前に規模を確認する」ための唯一の安全機構であり、
過小報告（除外の見落とし）も過大報告（65535倍）も判断を誤らせる。

**修正**: 実際のiterator（`socket_targets_shard`）と同じ規則で数える。socket targetは
port積を掛けず1件、netはexcludesを引く。同じ値を`metrics.targets_total`にも使う。
IPv6かつfull/discoveryの場合はF-02の扱いと整合させる。

---

### F-10 compile時にbuffer長とoffsetの整合を検証しない

**場所**: `src/dsl/compiler.rs:158-184`

`recv_exact`のバイト数、`pack`の型、`concat`のsourceから各bufferの長さは
compile時に静的に決まるが、`extract`/`crc32`/`bytes_eq`のoffset・lengthとの
整合は検査していない。

**実証**: 4バイトbufferに対する`extract: {type: u32le, offset: 900}`が
`--dry-run`（= probe compile）を通過する。

実行時は`slice()`が`InvalidData`を返し、`classify()`が`invalid_response`に分類する。
つまりprobe定義の誤りが、全ホストで「相手が異常な応答を返した」として記録される。
C2判定ツールとしては、誤ったprobeが「responsive」統計を汚染する形になる。

**修正**: compilerでbuffer長テーブルを持ち、`offset + 型サイズ`、`offset + length`が
buffer長を超える場合にbailする。長さが静的に決まらないbufferは現状存在しない。

---

### F-11 `bytes_eq`の空hexが常に真になる

**場所**: `src/dsl/compiler.rs:392-397`、`src/probe/executor.rs:213-216`

`parse_hex("")`は`Ok(vec![])`を返し、compilerはこれを拒否しない。実行時は
`x.get(offset..offset+0)`が`Some(&[])`になり、空同士の比較で`true`が確定する。

**実証**: `bytes_eq: {source: response, offset: 0, hex: ""}` を含むprobeがcompileを通る。

`send: {hex: ""}`は明示的に拒否しているのに、判定側は素通しになっている。
YAMLの記述ミス（`hex:`の値が空、変数展開の失敗）が、そのまま`confirmed: true`の
誤検知として出力される。C2帰属に使う出力なので影響は小さくない。

**修正**: `bytes_eq`のhexを1バイト以上必須にする。あわせて`match`条件が
リテラル同士の比較のみで成立するケース（`eq: {left: 1, right: 1}`）も
警告対象にすることを検討する（テストでは使っているため拒否ではなくwarn）。

---

### F-12 match stepが複数あるとconfidence/statusが不整合になる

**場所**: `src/probe/executor.rs:125-149`

```rust
matched = eval_bool(condition, &regs, &bufs);
if matched { override_conf = *confidence; override_status = ...; }
```

`matched`は各`Match`で上書きされるが、`override_conf`/`override_status`は
真になった時点の値が残り続ける。match stepが2つあり、1つ目が真・2つ目が偽の場合、
最終出力は `confirmed: false, confidence: 0.95, status: <1つ目のstatus>` になる。

compilerは`has_match`が1つ以上あることしか見ておらず、複数のmatch stepを許可している。

**修正**: 次のいずれか。

- `Match`ごとにoverrideを確定させる（偽ならクリアする）
- compile時にmatch stepを1つに制限し、複合条件は`all`/`any`で書かせる（spec §12の
  意図に近い）

---

### F-13 schedulerのhost semaphoreとdedup setが解放されない

**場所**: `src/probe/scheduler.rs:43`、`55`、`71-81`

- `hosts: Mutex<HashMap<IpAddr, Arc<Semaphore>>>` はエントリを削除しない
- `seen: Mutex<HashSet<(IpAddr, u16, Arc<str>)>>` もスキャン終了まで単調増加

10,000 IP × 平均5 open portのspec想定なら問題ないが、`--scan-mode probe`に
大量の`IP:PORT`を投入する運用や、open portが多いレンジでは数百万エントリになる。

加えて両方が単一の`tokio::sync::Mutex`であり、probe 1件あたり2回ロックを取る。
`--probe-concurrency 10000`ではここが直列化点になり、spec §44のPhase 2目標
（10,000+ concurrent）でスループットの上限を作る可能性がある。

**修正**: hostエントリは待機数0になった時点で削除する（`Arc::strong_count`または
明示的なrefcount）。dedupはIPでshardしたmapに分割するか、`DashMap`等のlock-free構造へ移す。
ベンチはPERFORMANCE.mdの受入試験に含める。

---

### F-14 port_stateが常にopen、syn_rtt_msが常にnull

**場所**: `src/discovery/linux.rs:75-101`、`src/probe/scheduler.rs:132-135`、`184-187`

受信側はSYN/ACKのみを処理し、RSTを見ていない。`OpenPort.syn_rtt_ms`は常に`None`で
埋められ、`DiscoveryResult.port_state`は`"open"`のリテラルしか生成されない。

したがって:

- spec §6.1のCLOSED / FILTERED区別が出力に存在しない
- spec §26のJSON例にある`syn_rtt_ms`が常に欠落する
- `--output-mode all`が「open portと全probe結果」であって、closed portは含まない
  （README表の記述はコードと一致しているが、spec §28の`all`の意図とはずれる）

**修正**: 受信側でRSTを`ports_closed`として計上する（出力に含めるかは`--output-mode`で
制御）。送信時刻はcookieに載せられないため、`(dst, port)`→送信時刻の
リングバッファかタイムバケットで近似RTTを算出する。実装しない場合は
spec §26のJSON例と§6.1から`syn_rtt_ms`/CLOSED表記を落として、仕様と実装を揃える。

---

### F-15 source portがephemeral範囲と衝突、cookie secretが固定値

**場所**: `src/discovery/linux.rs:61-62`、`360-362`

```rust
let source_port = 40000 + (std::process::id() % 20000) as u16;  // 40000-59999
let secret = 0xC2A5_2026u32;
```

1. **ephemeral portとの衝突**: Linux既定の`ip_local_port_range`は32768–60999。
   選択範囲が完全にその内側にあるため、同一ホストの正規のoutbound接続に同じ
   ローカルポートが割り当たりうる。その接続のSYN/ACKがreceiverのフィルタを
   通過する可能性がある（cookie照合で大半は落ちるが、設計としては避けるべき）。
2. **cookie secretが公開定数**: `cookie()`はソース公開の固定値のみに依存するため、
   off-pathからACK番号を計算してSYN/ACKを偽装し、任意のIP:PORTを
   open portとして注入できる。C2候補リストの汚染につながる。
3. **カーネルRSTの抑止手順が未文書化**: 送信元ポートにsocketをbindしていないため、
   カーネルは受信したSYN/ACKにRSTを返す。SYN scanでは通常の挙動だが、
   `iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP`相当の運用手順が
   README/PERFORMANCE.mdにない。

**修正**: secretを起動時に乱数生成する（worker間はCLIまたは環境変数で共有）。
source portは`ip_local_port_range`を読んで範囲外を選ぶか、実際にbindして占有する。
RST抑止のiptablesルールをPERFORMANCE.mdの手順に追加する。

---

## 低

### F-16 `-iL targets.txt`がspec記載どおり動かない

**場所**: `src/cli/mod.rs:40-41`、`spec.md` §9・§29

clapの`alias = "iL"`はlong flagの別名なので`--iL`になる。`-iL targets.txt`は
`-i` の値が`L`と解釈され、`targets.txt`が余剰引数エラーになる。

**実証**: `-iL <file>` → `error: unexpected argument '<file>' found`。
`--iL <file>` と `-i <file>` は動作する。

**修正**: spec §9・§29の例を`-i`に修正する（READMEは既に`-i`表記で正しい）。
nmap互換の`-iL`を残したい場合は、引数前処理で`-iL`を`--input-list`へ書き換える。

### F-17 `--output-mode open`でもprobeを実行して結果を捨てる

**場所**: `src/probe/scheduler.rs:114-119`

`--scan-mode full --output-mode open`では、probeを全て実行したうえで
`should = false`により出力しない。無駄な接続とtimeout待ちが発生する。

**修正**: `output_mode == Open`かつ`scan_mode == Full`の場合はprobe planをskipするか、
起動時に「probeは実行されるが出力されない」ことを警告する。

### F-18 error分類の欠落と誤分類

**場所**: `src/probe/executor.rs:219-233`

- spec §34の`protocol_mismatch`と`internal_error`が生成されない
- `classify()`が`e.to_string()`の部分一致で判定するため、TLS handshake timeoutの
  メッセージ`"TLS timeout"`は`contains("tls")`にヒットし、`connect_timeout`ではなく
  `tls_error`になる。spec §33の「timeoutを3種類に分ける」という意図とずれる

**修正**: transport層で型付きエラー（enum）を返し、文字列一致をやめる。
`protocol_mismatch`はmatch不成立かつresponsiveのケースに割り当てるのが自然。

### F-19 出力flushがBufWriter任せでstreamingにならない

**場所**: `src/output/mod.rs:47`、`121-123`

`BufWriter`は既定8 KiBが埋まるまで書き出さず、明示flushは`shutdown()`のみ。
`--output-mode matched`のような低頻度出力では、スキャン終了までファイルに
1行も現れない。spec §26が挙げるstreaming JSONLの利点（実行中のjq/OpenSearch投入）が
得られない。multi-processではworkerのstdoutにも同じ遅延がかかる。

**修正**: 一定間隔（例: 1秒）または一定件数でflushする。matched件数が少ない
運用を前提に、`--flush-interval`を用意してもよい。

### F-20 metricsのラベルと実体が乖離、live statusが未実装

**場所**: `src/discovery/linux.rs:140-145`、`src/metrics/mod.rs:60-79`、`src/main.rs:100-103`

- `ports_scheduled`に送信済みpacket数を加算しており、`syn_packets_sent`と常に同値。
  spec §36は両者を別指標として定義している。probeモードでは0のまま
- multi-processでは各workerが`targets_total`に全体件数を格納するため、
  summaryの合計がprocesses倍になる（実証: worker 1/2ともに`targets=1`）
- spec §36の実行中status表示（current rate、queue depth、activeの定期出力）が
  未実装で、summaryは終了時の1行のみ

**修正**: `ports_scheduled`はjob生成側で加算する。workerは自分のshard件数を入れる。
定期status出力（`--status-interval`、stderr）を追加する。

### F-21 `--probe-dir`の再帰が1階層のみ

**場所**: `src/dsl/compiler.rs:23-40`

`probes/<family>/<name>.yaml`は読めるが、それより深い階層は無視される。
spec §50のProbe Registryを階層化すると読み落とす。

**修正**: 深さ制限付きの再帰walkにする（symlinkループ対策込み）。

### F-22 probe実行時のメモリ上限がない

**場所**: `src/probe/executor.rs:55-101`

`recv_exact`は1件1 MiBまでだが、step数に上限がない。1 MiBのYAMLには多数の
`recv_exact`を書けるため、1接続あたり数十MiBのbufferを確保しうる。
`--probe-concurrency 10000`ではGiB級になる。probeは運用者が書く前提なので
攻撃面ではないが、事故防止のガードがない。

**修正**: compile時に「probe 1本のbuffer合計上限」を検証する（例: 4 MiB）。
`probe_concurrency × 上限`を起動時に表示する。

### F-23 `pack`が値を無言で切り詰める

**場所**: `src/probe/executor.rs:180-190`

`pack: {type: u8, value: 300}`は`44`になる。`compute`の結果が想定より大きい場合も
同様に静かに切れるため、送信frameが意図と異なってもDSL作者は気づけない。

**修正**: リテラル値はcompile時に型範囲を検証する。register由来の値は実行時に
切り詰めが起きたら`probe_error`にするか、明示的な`truncate`指定を必須にする。

### F-24 `bytes_eq`のoffset加算がオーバーフローしうる

**場所**: `src/probe/executor.rs:215`

`x.get(*offset..offset + bytes.len())` は`offset`が極端に大きいとdebug buildでpanicする。
`slice()`（同ファイル158-161行）は`saturating_add`を使っており不整合。

**修正**: `saturating_add`に統一する。F-10のcompile時検証を入れれば実害はなくなるが、
防御的に両方直すのが望ましい。

### F-25 受信側がOpenPort送信失敗を無視して走り続ける

**場所**: `src/discovery/linux.rs:92-101`

`blocking_send`が失敗（scheduler側が終了）してもメトリクスを戻すだけでループを継続する。
Phase 2が異常終了しても、SYN送信は最後まで走り切る。

**修正**: 送信失敗時はreceiverループを終了し、senderにも停止を伝える。

### F-26 `serde_yaml` 0.9はunmaintained

**場所**: `Cargo.toml:26`

`serde_yaml` 0.9はメンテナンス終了（RUSTSEC-2024-0320）。今後のセキュリティ修正は
提供されない。移行先は`serde_yml`、`serde_yaml_ng`、`saphyr`系など。

なお、YAML alias展開によるメモリ増幅（YAML bomb）は`serde_yaml`側の
repetition limitで拒否されることを実測で確認した（`repetition limit exceeded`）。
現時点で追加のガードは不要。

**修正**: 依存の移行計画を持つ。あわせてCIに`cargo deny`または`cargo audit`を追加する。

---

## 仕様どおりに実装されていることを確認した点

問題として挙げていないが、レビューで正しさを確認した箇所を記録する。

- `sendmmsg`に渡す`PacketSlot`、`iovec`、`mmsghdr`はいずれも起動時に容量確保済みの
  `Vec`で、syscall中に再配置されない（`push`は`capacity`を超えないようガードされている）
- partial sendは未送信の`mmsghdr`から再開し、個別失敗・0件送信は対象jobだけをskipする
- `sockaddr_in.s_addr`に`u32::from_ne_bytes(octets)`を使うのはnetwork byte orderとして正しい
- raw socketはRAIIでclose、`IP_HDRINCL`設定失敗時もfdをcloseしている
- probe planは`plan_order`（n520=10 → winos=20 → vvas=30）で整列し、confirmedで
  後続を停止する。spec §21と一致
- global / per-host / per-probe の3段Semaphoreは取得順が一定（global → host → probe）で
  デッドロックしない。per-probe制限は統合テストで実測されている
- 重複排除キーは`(IP, PORT, PROBE)`で、spec §32を満たす
- `PortSet`の範囲マージとshard分割は、全workerの和が単一プロセスの結果と一致し、
  重複がないことがテストで担保されている
- Winos probeは固定packetを埋め込まず、`compute`/`pack`/`concat`から15バイトの
  request frameを生成しており、参照frameとバイト一致することがテストで確認されている
- DSLはループ・再帰・任意関数・OS command・filesystem accessを提供しておらず、
  spec §13の禁止事項を満たす
- output writerのエラーは共有shutdownへ伝播し、producer/schedulerを止めてハングしない。
  完了済み行はrecord単位flushと定期`sync_data`で保持する

---

## 修正実装の概要

### 新規モジュール

| ファイル | 目的 |
|---|---|
| `src/shutdown.rs` | プロセス全体で1度だけ登録するCtrl+C listener（F-05、F-06） |
| `src/discovery/cookie.rs` | SYN/ACK相関cookieと送信時刻の符号化（F-14、F-15） |

`cookie.rs`はプラットフォーム非依存にした。相関の計算はLinux固有ではなく、Linux向け
test targetをビルドできない開発hostでも検証できる必要があるため。

### 変更点

| ID | 実装 |
|---|---|
| F-01 | `EnvFilter::builder().with_default_directive(LevelFilter::INFO)`へ変更（`src/main.rs`） |
| F-02 | `TargetSet::has_ipv6_nets`と`Args::check_target_support`を追加し、full/discoveryでIPv6を起動時エラーにした |
| F-03 | 送信前に`next = next.max(Instant::now())`でクレジット蓄積を打ち切り |
| F-04 | 経路解決失敗と IPv6 をdestination単位でskipし、`targets_skipped`へ計上 |
| F-05 | `Shutdown::listen()`を起動時に1度だけ呼び、producer・scheduler・出力が同じhandleを見る。実行中probeは`--shutdown-grace`まで待ち、超過時はabortしてから出力をflushする。2回目のCtrl+Cで即時終了 |
| F-06 | 親プロセスもlistenerを登録し、worker出力を集約してからflush。猶予超過時のみworkerをkillする |
| F-07 | `type: tls`かつ`insecure_tls != true`をcompile時に拒否。空root storeによる常時失敗を解消し、TLS timeoutは`connect_timeout`へ分類 |
| F-08 | `TargetSet::iter_sockets`を追加し、`IP:PORT`にも除外を適用 |
| F-09 | `host_count`（除外を減算）、`target_count`、`job_count`を追加。後にdry-runは削除したが、metricsと実イテレーションの一致はunit testで維持 |
| F-10 | compilerがbuffer長表を持ち、`extract`/`crc32`/`bytes_eq`のoffset・lengthを静的検証 |
| F-11 | `bytes_eq`の空hexと、空の`all`/`any`を拒否 |
| F-12 | match stepを1つに制限し、executor側でもmatchごとにconfidence/status overrideを確定 |
| F-13 | host semaphoreを参照カウント付きにして0で削除。dedup setを64 shardへ分割 |
| F-14 | RSTを`ports_closed`として計上。sequence下位8 bitに4 ms刻みの送信時刻を埋め、`syn_rtt_ms`を算出（`--syn-timeout`が1024 msを超える場合は出力しない） |
| F-15 | cookie鍵を`/dev/urandom`から起動ごとに生成。cookieはavalanche mix後に24 bitへ切り出す。送信元ポートは`ip_local_port_range`の外から選択。RST抑止手順をPERFORMANCE.mdへ追記 |
| F-16 | `-iL`をparse前に`--input-list`へ書き換え（`cli::normalize_arguments`）。worker起動時の引数にも適用 |
| F-17 | `Args::runs_probes()`を追加し、`--output-mode open`ではprobeを読み込まず実行もしない |
| F-18 | `ProbeFailure` enumを導入し、失敗地点で分類。`protocol_mismatch`と`internal_error`を追加 |
| F-19 | `--flush-interval`（既定1000 ms）を追加し、出力taskと親プロセスが定期flush |
| F-20 | `ports_scheduled`をjob生成側で計上。`ports_closed`・`targets_skipped`を追加。`--flush-interval`または5秒間隔でstatusを出力。`targets`が合計不可であることをREADMEに明記 |
| F-21 | probe directoryを深さ8まで再帰。symlinkは辿らない |
| F-22 | probe 1本のbuffer合計を4 MiBに制限 |
| F-23 | `pack`のリテラル範囲をcompile時に検証。実行時の切り詰めは`internal_error`。意図的な切り詰めは`wrap: true` |
| F-24 | `saturating_add`へ統一。offset過大でもpanicせずfalse |
| F-25 | OpenPort送信に失敗したらreceiverループを終了 |

### 追加したtest

- `src/discovery/cookie.rs` — cookie復元、timestamp bitとの分離、RTT算出、wrap、近傍destinationの衝突
- `src/target/mod.rs` — 除外がsocket targetへ適用されること、8パターンで件数が実イテレーションと一致すること
- `src/probe/scheduler.rs` — host limitの解放、dedupのshard動作
- `src/dsl/compiler.rs` — 範囲外read、空`bytes_eq`、複数match、pack切り詰め、TLS opt-in、buffer予算
- `src/cli/mod.rs`、`src/shutdown.rs`、`src/metrics/mod.rs` — 引数書き換え、IPv6拒否、probe skip判定、shutdown handle、counter表示
- `tests/mock_valleyrat.rs` — IPv6拒否、`-iL`、probe定義エラー、`protocol_mismatch`、`connection_refused`

### 互換性への影響

- `transport.type: tls`のprobeは`insecure_tls: true`が必須になった。同梱の`n520.yaml`は既に指定済み
- match stepを2つ以上持つprobeはcompileできなくなった。`all`/`any`/`not`で合成する
- `pack`で型幅を超えるリテラルを使うprobeは`wrap: true`が必要
- `--output-mode open`はprobeを実行しなくなった。probe結果が必要な場合は`all`または`responsive`を使う
- CLIに`--flush-interval`と`--shutdown-grace`を追加した。既定値のみで従来と同じ運用ができる
- 後続修正で`--log-level`と`--log-file`を追加し、Raw SYN個別送信エラーはログ記録後にskipして継続する
- 出力は各record後にflush、定期間隔と終了時に`sync_data`し、task errorでもdrain後に元のエラーを返す
