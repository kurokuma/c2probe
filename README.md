# c2probe

`c2probe`は、C2インフラ探索を目的としたLinux向け高速TCPスキャナーです。
Raw SYNでopen port候補を絞り込み、NSEやマルウェア解析から変換した制限付きYAML
DSLをIRへ一度だけコンパイルして、TokioベースのExecutorでC2固有応答を検証します。

## 対応環境

| 項目 | 対応状況 |
|---|---|
| 実行OS | Linux（全モード）、Windows（probeのみ） |
| CPU | x86_64、aarch64 |
| Raw SYN discovery | IPv4 |
| probe-only | IPv4、IPv6 |
| Windows | probe-only、DSL開発・テスト |
| macOS | 初期要件外 |

IPv6 targetは`--scan-mode probe`でのみ受け付けます。`full`/`discovery`にIPv6を渡した場合は起動時にエラーで停止します。

Raw SYNには`CAP_NET_RAW`またはroot権限が必要です。常時rootで実行せず、可能な限りビルド済みバイナリへ`CAP_NET_RAW`だけを付与してください。

## リポジトリ構成

```text
.
├── Cargo.toml / Cargo.lock
├── .gitignore
├── Makefile
├── probes/                  # family別の24 application probe YAML
├── scripts/
│   ├── build-linux.sh       # Linux上でLinux版を作成
│   └── build-windows.ps1    # Windows上でWindows版を作成
├── src/
│   ├── main.rs             # c2probe
│   └── bin/nse2yaml.rs     # strict NSE converter
└── tests/
    ├── mock_valleyrat.rs
    └── nse_converter.rs
```

## Linux上でビルドする

### 必要なパッケージ

- Rust 1.94以降（Edition 2024）
- Cコンパイラと標準ビルドツール
- CMake、pkg-config
- `libcap2-bin`（`setcap`を使う場合）

Debian/Ubuntuの例:

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libcap2-bin
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

テスト・Clippy・release build・配布用tarball作成をまとめて実行します。

```bash
chmod +x scripts/build-linux.sh
./scripts/build-linux.sh
```

成果物:

```text
dist/c2probe-0.1.0-linux-x86_64.tar.gz
dist/c2probe-0.1.0-linux-x86_64.sha256
```

aarch64 Linux上で実行した場合はファイル名が`linux-aarch64`になります。単純な開発用
ビルドだけなら次のコマンドでも構いません。

```bash
cargo build --locked --release
./target/release/c2probe --help
./target/release/nse2yaml --help
```

## Windows上でWindows版をビルドする

Windows用スクリプトはWindowsネイティブの`c2probe.exe`を作成します。Linux版へのクロスコンパイルは行いません。WindowsではRaw SYN discoveryを利用できないため、生成物は`probe`モード、DSL開発、Mock C2テスト用です。

必要な環境:

- Rust 1.94以降の`stable-x86_64-pc-windows-msvc`またはARM64 MSVC toolchain
- Visual Studio 2022 Build ToolsのC++ build tools
- CMake
- PowerShell 7またはWindows PowerShell 5.1

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\build-windows.ps1
```

成果物:

```text
dist/c2probe-0.1.0-windows-x86_64.zip
dist/c2probe-0.1.0-windows-x86_64.sha256
```

出力先は`-OutputDirectory`で変更できます。

```powershell
.\scripts\build-windows.ps1 -OutputDirectory F:\artifacts\c2probe
```

## スキャン実行

対象と必要なprobeを指定すると、引数検証後に直ちにスキャンを開始します。
対象範囲、除外、rateは実行前に確認してください。

```bash
./c2probe \
  -t 192.0.2.10 \
  -p all \
  --scan-mode full \
  --probe-dir probes/valleyrat \
  --syn-rate 10000 \
  --max-rate 10000 \
  --syn-batch-size 64 \
  --probe-concurrency 1024 \
  --per-host-concurrency 32 \
  --per-probe-concurrency 256 \
  --output-mode matched \
  --format jsonl \
  --output result.jsonl
```

## オプション一覧と使い分け

単位は特記がなければscan全体の設定です。`--processes`を2以上にした場合、rate、thread数、concurrencyは各workerへ分配されるため、指定値がworkerごとに掛け算されることはありません。

### 対象とport

| オプション | 既定値 | 内容と違い |
|---|---:|---|
| `-t, --target <TARGET>` | なし | IPまたはCIDRを直接指定します。複数回指定できます。`probe` modeだけは`IP:PORT`とIPv6の`[IP]:PORT`も指定できます |
| `-i, --input-list <FILE>` | なし | targetをファイルから読みます。`-iL`も同じ意味です。`-t`と併用した場合は両方をscanします |
| `-p, --ports <PORTS>` | `1-65535` | IP/CIDRに展開するportです。`80,443,8000-8100`または`all`を指定します。`probe` modeで明示した`IP:PORT`には、その明示portを使用します |
| `--exclude <TARGET>` | なし | 除外するIP/CIDRを直接指定します。複数回指定でき、明示した`IP:PORT`にもIP単位で適用します |
| `--exclude-file <FILE>` | なし | 除外するIP/CIDRをファイルから読みます。`--exclude`と併用した場合は両方を適用します |

target/input/excludeファイルでは空行と`#`以降を無視します。`full`と`discovery`のRaw SYNは
IPv4専用です。IPv6へ接続する場合は`--scan-mode probe`を使用してください。

### scanとprobe

| オプション | 既定値 | 内容と違い |
|---|---:|---|
| `--scan-mode <MODE>` | `full` | 処理段階を選びます。`full`はRaw SYN後にopen portをprobe、`discovery`はRaw SYNだけ、`probe`はRaw SYNを行わず指定先へ直接接続します |
| `--probe <FILE>` | なし | 読み込むprobe YAMLを1ファイルずつ指定します。複数回指定できます |
| `--probe-dir <DIR>` | なし | ディレクトリ内のprobe YAMLをまとめて読み込みます。`--probe`と併用できます |
| `--probe-param <NAME=VALUE>` | なし | 鍵、build ID、期待証明書、IP pinなど、review済みprofile値をYAMLへ渡します。複数回指定できます |
| `--output-mode <MODE>` | `matched` | 出力する結果の条件を選びます。`open`だけはprobe自体を実行しません。詳細は「出力」を参照してください |
| `--retries <COUNT>` | `0` | timeout、connection reset、probe errorなど一時的な失敗に対する追加試行回数です。初回を含む最大試行回数は`COUNT + 1`です |

`--scan-mode`は「どの処理を行うか」、`--output-mode`は「どの結果を残すか」を制御します。
ただし`--output-mode open`は不要なapplication接続を避けるためprobe実行も無効にします。

### rate、並列度、batch

| オプション | 既定値 | 内容と違い |
|---|---:|---|
| `--syn-rate <PPS>` | `100000` | 実際に使用するRaw SYN送信rateです。application probeの接続rateではありません |
| `--max-rate <PPS>` | `100000` | 誤設定防止用の上限です。`--syn-rate`がこの値を超えると起動を拒否します。別の動的rate limiterではありません |
| `--syn-batch-size <COUNT>` | `64` | Linuxの1回の`sendmmsg(2)`へまとめるSYN数です。範囲は1–1024で、rateそのものは変更しません |
| `--processes <COUNT>` | `1` | scanner worker process数です。process分離とCPU利用を増やします。範囲は1–64です |
| `--threads <COUNT>` | 論理CPU数 | Tokio worker threadの合計です。process数とは異なり、同一process内の非同期処理を実行します |
| `--probe-concurrency <COUNT>` | `1024` | scan全体で同時実行できるapplication probe plan数の上限です |
| `--per-host-concurrency <COUNT>` | `32` | 同じIPへ同時接続できるprobe数の上限です。1台への集中を抑えます |
| `--per-probe-concurrency <COUNT>` | `256` | 同じprobe定義を同時実行できる数の上限です。特定protocolへの偏りを抑えます |
| `--cpu-affinity <CPUSET>` | なし | Linux CPU ID（例:`0,2-5`）へworker/threadを割り当てます。並列数を増やすオプションではありません |

3種類のconcurrencyは同時に適用され、最も先に到達した上限で待機します。例えばglobalが1024でも、同一IPに対しては`--per-host-concurrency 32`を超えて接続しません。`--threads`は実行thread数、concurrencyは待機中のnetwork I/Oを含む同時probe数なので、同じ値にする必要はありません。

### timeoutと終了処理

| オプション | 既定値 | 単位 | 内容と違い |
|---|---:|---:|---|
| `--connect-timeout <VALUE>` | `750` | ms | application probeのTCP接続確立を待つ時間です |
| `--read-timeout <VALUE>` | `1000` | ms | 接続後、probeが必要とする応答受信を待つ時間です |
| `--syn-timeout <VALUE>` | `1000` | ms | 全SYN送信完了後に遅延したSYN/ACKまたはRSTを受け取るための最終待機時間です |
| `--shutdown-grace <VALUE>` | `10` | 秒 | Ctrl+Cやtask停止後に実行中probeの完了を待つ猶予です。timeout設定とは独立しています |

### 結果、ログ、耐久性

| オプション | 既定値 | 内容と違い |
|---|---:|---|
| `--format <FORMAT>` | `jsonl` | 結果のserializationを`jsonl`または`csv`から選びます。複数processではJSONLのみです |
| `--output <FILE>` | stdout | scan結果を書きます。ログファイルではありません。各完成recordを逐次flushします |
| `--log-level <LEVEL>` | `info` | stderrと`--log-file`へ出す最低ログlevelです。`trace/debug/info/warn/error/off`を選択します |
| `--log-file <FILE>` | なし | stderrへのログを止めず、同じログを指定ファイルにも追記します。`--output`と同じpathは指定できません |
| `--flush-interval <VALUE>` | `1000` | 出力ファイルへ`sync_data`する間隔（ms）です。recordの即時flush間隔ではありません |

`--output`は機械処理するscan結果、`--log-file`は進捗・警告・エラーです。両者を分離することで、
JSONLへログ文字列が混ざることを防ぎます。recordは毎回flushされるためscan中にも読めますが、
電源断に対するdisk同期頻度を短くしたい場合だけ`--flush-interval`を小さくしてください。

## ログ

ログは既定でstderrへ`info`以上を出力します。`--log-level`は`trace`、`debug`、`info`、
`warn`、`error`、`off`から選択できます。`--log-file`を指定するとstderrに加えてファイルへ
追記します。`RUST_LOG`を併用するとmodule単位のfilterを追加できます。

```bash
./c2probe \
  -i targets.txt \
  -p 80,443 \
  --scan-mode discovery \
  --output-mode open \
  --output open.jsonl \
  --log-level debug \
  --log-file c2probe.log
```

Raw SYN送信をkernelが拒否した場合、scan全体は停止せず、その`IP:port`だけをskipします。
警告ログには対象とOS errorを出し、summaryの`send_errors`と`skipped`へ計上します。

```text
WARN raw SYN send failed; skipping target ip=192.0.2.10 port=25 error=Operation not permitted (os error 1)
```

`trace`はpacket job単位、`debug`はRaw SYN batch単位の詳細を出すため、大規模scanでは
ログ量が非常に多くなります。通常運用は`info`、送信失敗の記録だけなら`warn`を推奨します。

## マルチスレッドとマルチプロセス

`--threads`は全workerに配分するTokio worker threadの合計、`--processes`は起動する
scanner worker process数です。親プロセスは集約専用の1 thread runtimeで動作します。

```bash
./c2probe \
  -i targets.txt \
  -p all \
  --probe-dir probes/valleyrat \
  --processes 4 \
  --threads 16 \
  --cpu-affinity 0-15 \
  --syn-rate 250000 \
  --max-rate 250000 \
  --probe-concurrency 10000 \
  --per-host-concurrency 64 \
  --per-probe-concurrency 1024 \
  --format jsonl \
  --output result.jsonl
```

この例では、4 workerへ概ね4 threadずつ、合計250,000 pps、合計10,000 Probe Plan、
同一host合計64 connection、同一probe合計1,024 connectionを分配します。各workerは同じtarget全体を展開せず、port列を
`worker_id`ごとのstrideで分割するため、同じ`IP:PORT`を重複scanしません。workerの
JSONLは親プロセスが1本の出力へ集約します。

`--cpu-affinity`はLinux CPU ID（例: `0,2-5`）を指定します。複数processではCPU集合も
workerへ分割されます。`--syn-batch-size`は1回の`sendmmsg(2)`へまとめるSYN数で、既定値は
64、範囲は1–1024です。設計と測定手順は[docs/PERFORMANCE.md](docs/PERFORMANCE.md)を参照してください。

現在の制約:

- `--processes`は1–64
- process数はthreads、syn-rate、global/per-host/per-probe concurrency以下であること
- マルチプロセス出力はJSONLのみ。CSVは単一プロセスで使用すること
- `--syn-rate`、`--threads`、global/per-host/per-probe concurrencyはprocessごとの値ではなく全体値
- worker stderrのstatus表示順は並列実行のため一定ではない
- CPU affinityはLinuxのみ。指定CPUがcpuset内で利用できない場合は起動に失敗する
- summaryの`targets`はworkerごとの対象IP数。sharding はport列を分割するため全workerで同じ値に
  なり、合計してはならない。`scheduled`、`syn_sent`、`open`、`probes`はworkerごとの実測値

## Scan Mode

### full

Raw SYN discovery後、open portにだけapplication probeを実行します。標準モードです。

```bash
./c2probe -t 192.0.2.10 -p all --scan-mode full \
  --probe-dir probes/valleyrat
```

### discovery

Raw SYN discoveryのみを実行し、open portを出力します。

```bash
./c2probe -t 192.0.2.0/24 -p 1-10000 --scan-mode discovery \
  --output-mode open --output open-ports.jsonl
```

### probe

既知の`IP:PORT`へ直接probeを行います。IPv6は`[address]:port`形式です。このモードは
Raw socket権限を必要としません。

```bash
./c2probe -t 127.0.0.1:48122 --scan-mode probe \
  --probe probes/valleyrat/vvas.yaml
```

## 入力ファイルと除外

```text
# targets.txt
192.0.2.10
198.51.100.0/24
203.0.113.0/28
```

```bash
./c2probe -i targets.txt -p 1-65535 \
  --exclude 198.51.100.20 \
  --exclude-file exclusions.txt \
  --probe-dir probes/valleyrat
```

空行と`#`以降は無視されます。

## 出力

デフォルトはストリーミングJSONLです。`--format csv`を指定すると固定カラムと
`extra_json`を持つCSVになります。

```bash
./c2probe -t 127.0.0.1:48122 --scan-mode probe \
  --probe probes/valleyrat/vvas.yaml \
  --format csv --output result.csv
```

出力モード:

| 値 | 内容 |
|---|---|
| `all` | open portと全probe結果 |
| `open` | open portのみ。probeは実行しません |
| `responsive` | application応答があったprobe |
| `detected` | confirmedまたはprobable。経路・登録形状の中確度判定も含めます |
| `matched` | confirmedのみ。既定値 |

`--output-mode open`はprobe結果を出力しないため、`--scan-mode full`であってもprobe接続を
行いません。

JSONL/CSVは1レコード書くたびにflushするため、長時間scanの途中でも完成済みの行を確認できます。
さらに`--flush-interval`（既定1000 ms）ごとに`sync_data`し、正常終了、Ctrl+C、別taskの
エラー時にもqueueをdrainして最終同期してから終了します。したがって途中で一部処理が失敗しても、
それ以前に確定した結果を空のファイルとして失いません。

## 中断とシャットダウン

Ctrl+Cはプロセス起動時に1度だけ登録され、scanのどの段階でも有効です。

1. 新規jobとprobe planの生成を停止する
2. 実行中のprobeを`--shutdown-grace`秒（既定10）まで待つ
3. ResultQueueをflushし、出力を閉じる
4. summaryを出力する

猶予時間内に終わらないprobeは打ち切りますが、出力ファイルは必ずflushしてから終了するため
JSONLが行途中で壊れることはありません。マルチプロセスでは親プロセスもworkerの残り出力を
集約してからflushします。すぐに止めたい場合はCtrl+Cを2回入力してください（2回目は
未flushの出力を破棄して即座に終了します）。

## Probe DSLの安全境界

DSLはネットワークfingerprint専用です。ループ、再帰、任意関数、OS command、
filesystem access、process execution、dynamic module loadingは提供しません。probe YAMLは
1 MiB以下に制限され、各受信bufferも1 MiB以下として起動時に検証されます。TCP、TLS、
plaintext prelude後の同一stream TLS upgrade、bounded frame/HTTP受信、RC4、Base64、gzip、
限定MessagePack string抽出をIRへcompileします。

起動時のcompileでは、実行前に次も検証します。probe定義の誤りが「相手の応答異常」として
記録されることを防ぐためです。

- `extract`、`crc32`、`bytes_eq`のoffsetとlengthが、対象bufferの静的長を超えないこと
- `bytes_eq`のhexが1 byte以上であること（空パターンは常にmatchしてしまうため）
- `match` stepがprobeにちょうど1つであること（複数あるとconfidenceの出所が曖昧になるため）
- `pack`の値が指定した型に収まること。切り詰めを許す場合は`wrap: true`を明示すること
- probe 1本が保持するbuffer合計が4 MiB以下であること
- scopeのIP/CIDRとport、HTTP method/path/header、regex、parameter型が有効であること
- `reject_if`のbuffer間prefix比較をcompileし、反射応答など明示した除外条件をmatchより優先すること

`transport.type: tls`は`insecure_tls: true`を必須とします。このビルドは証明書検証を行わない
ため、検証しないことをprobe側で明示させています。

同梱probeは[upstream scripts全12本](https://github.com/proshiba/AI-security-analysis/tree/main/analysis-framework/nmap/scripts)
をレビューし、application通信を持つものを24 YAMLへ展開したものです。DNS解決だけ、および
tcp-open観測だけのNSEは、偽のC2判定YAMLを作らずc2probe native機能へ対応付けています。
全件の対応、SHA-256、表現差は[docs/NSE_COVERAGE.md](docs/NSE_COVERAGE.md)にあります。

結果の確度は`confirmed`、`probable`、`observation`で分離されます。既定の`matched`は
confirmedだけ、`detected`はconfirmedとprobableを出力します。parameter付きYAMLを
directoryから読んだ際に値がなければ、そのruleだけ警告付きでskipします。明示した
`--probe`のparameter不足は設定ミスとして起動エラーになります。

Winos probeは固定済みpacketを埋め込まず、`compute`でcommandを算出し、`pack`で各整数を
指定endiannessのbufferへ変換し、`concat`したbufferを`send.source`で送信します。

```yaml
- pack: { name: length, type: u32le, value: 15 }
- pack: { name: command, type: u8, value: "$request_command" }
- concat: { name: request, sources: ["$length", "$command"] }
- send: { source: "$request" }
```

各bufferとconcat結果は1 MiBを上限とし、未定義buffer/register、重複名、複数命令を
含むstepはcompile時に拒否されます。

## NSEからYAMLへの変換

`nse2yaml`はNSEを実行せず、Lua sourceをtokenizeして対応profileの通信と判定定数を静的に
検証してからYAMLを生成します。自動converterのstrict profileは、レビュー済みValleyRAT
NSEの`winos`、`vvas`、`n520`です。残りは今回、人手レビュー、DSL拡張、scope/parameter
設定、registry compile testを経て保守対象YAMLへ変換しました。任意のNSEを汎用変換する
ものではありません。

```bash
./nse2yaml valleyrat-c2.nse \
  --output-dir generated-probes \
  --report generated-probes/conversion-report.json
```

生成物:

```text
generated-probes/
├── winos.yaml
├── vvas.yaml
├── n520.yaml
└── conversion-report.json
```

既存ファイルは既定で上書きしません。内容を確認して置換する場合だけ`--force`を指定します。
生成した3 YAMLは書き出す前に既存DSL compilerを通過します。未知の`require`、動的load、
`os`/`io`/`package`/`debug`、未知のsocket method、期待と異なる定数・network operation数は
変換エラーになります。未対応処理を黙って削除してYAMLを生成することはありません。

参照NSEに対する検証結果:

| NSE mode | 生成YAML | 判定 | 根拠 |
|---|---|---|---|
| `vvas` | `vvas.yaml` | コア判定同等 | `33 32 00`送信、14 byte受信、stage size `307214`、後続10 zero byte |
| `n520` | `n520.yaml` | コア判定同等 | TLS server-first 44 byte、session magic計算、先頭40 byteのCRC32 |
| `winos` | `winos.yaml` | 保守的部分同等 | 15 byte heartbeat、header由来XOR、command `0xc9/0xca/0xcb`を保持 |

Winos NSEのrequest reflection除外は`reject_if`で表現し、反射時はconfidence 0の
`winos_request_reflected`としてconfirmedにしません。宣言長15–64について生成ruleは15 byteの
最小control frameへ限定し、この差を`conversion-report.json`の`unsupported_semantics`へ記録します。接続・送受信
エラーstatusと診断用byte countもc2probe Executor側の表現へ正規化されます。

strict converterのfixtureと比較方法は[docs/NSE_CONVERSION.md](docs/NSE_CONVERSION.md)、
upstream 12本の全件対応は[docs/NSE_COVERAGE.md](docs/NSE_COVERAGE.md)を参照してください。

### family別の実行例

parameter不要な.NET RAT rule:

```bash
./c2probe -i targets.txt -p all --scan-mode full \
  --probe-dir probes/dotnet-rat --output-mode matched \
  --format jsonl --output dotnet-rat.jsonl
```

review済みRC4鍵を使うDarkComet rule（鍵はlog/resultへ出力しません）:

```bash
./c2probe -i targets.txt -p all --scan-mode full \
  --probe-dir probes/darkcomet \
  --probe-param darkcomet.key_base64='<BASE64_KEY>' \
  --output-mode matched --output darkcomet.jsonl
```

probableを含むFormBook route rule。domainを別途解決・検証したIPをtargetとpinの両方へ指定します:

```bash
./c2probe -t 192.0.2.10 -p 80 --scan-mode full \
  --probe probes/stealer-route/formbook-guloader.yaml \
  --probe-param formbook.expected_ip=192.0.2.10 \
  --output-mode detected --output formbook.jsonl
```

`--probe-dir probes`は全familyを全open portへ計画するため、通常は目的のfamily directoryを
選んでください。scope不一致ruleはnetwork接続前にskipされます。
