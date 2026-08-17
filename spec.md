# c2probe 高速C2ネットワーク探索ツール 設計書

## 1. 目的

`c2probe`は、大量のIPアドレスに対して高速なTCPポート探索を実施し、open portに対してC2固有のアプリケーションプロトコルを送受信することで、C2サーバーを識別するネットワーク調査ツールとする。

主要用途は以下。

* IP単体の調査
* CIDR単位の調査
* 大量IP/CIDRリストの一括調査
* 1-65535 TCPポート探索
* ポート番号が固定されないC2の探索
* C2固有プロトコルによるfingerprinting
* ValleyRAT/Winos等を初期対象とする
* 将来的に他マルウェア/C2プロトコルへ拡張する

Nmap NSEを直接実行するのではなく、NSEやマルウェア解析結果から必要なプロトコル処理を独自DSLへ変換し、起動時にIRへcompileしてRustネイティブExecutorで実行する。

---

# 2. 基本方針

処理を以下の2段階に分離する。

```text
Target
 IP / CIDR / file
       │
       ▼
┌───────────────────────┐
│ Phase 1               │
│ Port Discovery Engine │
│ Rust Native Raw SYN   │
└──────────┬────────────┘
           │
      open ports
           │
           ▼
┌───────────────────────┐
│ Phase 2               │
│ Probe Engine          │
│ DSL → IR → Rust       │
└──────────┬────────────┘
           │
           ▼
      C2 Detection
           │
           ▼
      JSONL / CSV
```

Phase 1ではアプリケーションデータを送信しない。

Phase 2ではPhase 1でopenと判定されたポートだけにC2固有プローブを実行する。

例えば10,000 IPに対して全TCPポートを確認する場合、

```text
10,000 × 65,535
= 655,350,000 ports
```

をPhase 1で探索する。

仮に各IP平均5ポートopenの場合、

```text
Phase 1:
655,350,000 SYN probes

Phase 2:
約50,000 application probes
```

となる。

---

# 3. 対象環境

初期バージョンはLinux専用とする。

対象アーキテクチャ:

```text
x86_64
aarch64
```

Rustで実装し、単一バイナリとして配布可能な構成とする。

Windows/macOS対応は初期要件に含めない。

---

# 4. 技術スタック

| 用途                      | 技術                            |
| ----------------------- | ----------------------------- |
| Language                | Rust                          |
| Async Runtime           | Tokio                         |
| CLI                     | clap                          |
| Serialization           | serde                         |
| JSON                    | serde_json                    |
| CSV                     | csv                           |
| CIDR                    | ipnet                         |
| TCP/TLS                 | tokio / socket2 / rustls      |
| Raw packet              | Linux raw socket / AF_PACKET系 |
| Hash/CRC                | crc32fast等                    |
| Logging                 | tracing                       |
| Queue                   | tokio::mpsc / crossbeam       |
| DSL parser              | serde_yaml等                   |
| Internal representation | 独自IR                          |

DSLのファイル表現としてYAMLを採用するが、YAMLそのものを実行言語とはしない。

```text
YAML
 ↓
DSL Parser
 ↓
AST
 ↓
Validator
 ↓
IR Compiler
 ↓
Compiled Probe
 ↓
Rust Executor
```

---

# 5. 全体アーキテクチャ

```text
                      c2probe
                         │
                         ▼
                 ┌──────────────┐
                 │ CLI / Config │
                 └──────┬───────┘
                        │
             ┌──────────┴──────────┐
             ▼                     ▼
       Target Parser          Probe Loader
             │                     │
       IP / CIDR / File       YAML DSL
             │                     │
             ▼                     ▼
       Target Stream          DSL Compiler
             │                     │
             │                     ▼
             │                Compiled IR
             │                     │
             ▼                     │
      Port Discovery               │
        Raw SYN                    │
             │                     │
             ▼                     │
        OpenPort Queue ◄───────────┘
             │
             ▼
       Probe Scheduler
             │
      ┌──────┼──────┐
      ▼      ▼      ▼
   Worker Worker Worker
      │      │      │
      └──────┼──────┘
             │
        Tokio Async I/O
             │
             ▼
        Probe Executor
             │
             ▼
         Match Engine
             │
             ▼
         Result Queue
             │
             ▼
         Output Writer
             │
       ┌─────┴─────┐
       ▼           ▼
     JSONL         CSV
```

---

# 6. Phase 1: Port Discovery Engine

## 6.1 目的

TCP接続を完全に確立せず、SYNベースでopen port候補を高速抽出する。

基本判定:

```text
SYN
 │
 ├─ SYN/ACK → OPEN
 │
 ├─ RST     → CLOSED
 │
 └─ timeout → FILTERED / NO RESPONSE
```

Phase 1ではC2プロトコル判定を行わない。

---

# 7. Port Discovery内部構造

```text
Target Stream
     │
     ▼
Target/Port Generator
     │
     ▼
Rate Limiter
     │
     ▼
Packet Sender
     │
     ▼
Network

Network
     │
     ▼
Packet Receiver
     │
     ▼
Response Correlator
     │
     ▼
OpenPort Queue
```

大量の

```text
(IP, PORT)
```

を全件メモリ上へ展開してはならない。

以下のようにstream生成する。

```text
Target iterator
   ×
Port iterator
   ↓
ScanJob
```

---

# 8. Port指定

以下をサポートする。

単一:

```bash
-p 443
```

複数:

```bash
-p 80,443,8443
```

range:

```bash
-p 10000-20000
```

混在:

```bash
-p 22,80,443,8000-9000,20000
```

全ポート:

```bash
-p all
```

`all`は、

```text
1-65535
```

を意味する。

---

# 9. Target指定

以下をサポートする。

単一IP:

```bash
-t 192.0.2.10
```

CIDR:

```bash
-t 192.0.2.0/24
```

IPv6:

```bash
-t 2001:db8::/120
```

ファイル:

```bash
-iL targets.txt
```

例:

```text
192.0.2.10
192.0.2.20
198.51.100.0/24
203.0.113.0/28
```

空行および`#`から始まる行は無視する。

---

# 10. Rate制御

スレッド数とは別にpacket rateを明示的に制御する。

```bash
--syn-rate 500000
```

単位:

```text
packets/sec
```

以下を別パラメータとする。

```text
--processes
--threads
--syn-rate
--probe-concurrency
```

役割:

```text
process
  CPU/NIC分散・障害分離

thread
  CPU並列処理

syn-rate
  Phase 1 packet送信速度

probe-concurrency
  Phase 2 TCP/TLS同時接続数
```

---

# 11. Phase 2: Probe Engine

Phase 1で検出された、

```text
IP:PORT
```

だけを対象とする。

```text
192.0.2.10:443
192.0.2.10:48221
198.51.100.20:56789
```

Probe Schedulerが利用するDSLを決定する。

---

# 12. Probe DSL

DSLは汎用プログラミング言語にはしない。

以下のネットワークfingerprint処理だけを表現する。

## 通信

```text
CONNECT_TCP
CONNECT_TLS

SEND
RECV
RECV_EXACT
RECV_UNTIL
```

## Binary処理

```text
PACK
CONCAT
SLICE

READ_U8

READ_U16_LE
READ_U16_BE

READ_U32_LE
READ_U32_BE

READ_U64_LE
READ_U64_BE
```

## 演算

```text
ADD
SUB
XOR
AND
OR

SHIFT_LEFT
SHIFT_RIGHT

CRC32

EQ
NE
LT
GT
```

## 判定

```text
MATCH_BYTES
MATCH_REGEX

ALL
ANY
NOT
```

## 出力

```text
SET
EMIT
```

---

# 13. DSLで禁止する機能

以下は基本的に実装しない。

```text
while
goto
再帰
任意function定義
OS command
filesystem access
process execution
dynamic module loading
```

DSLをLuaやPythonの代替言語にしない。

目的は、

```text
network protocol fingerprint
```

のみとする。

---

# 14. DSL Version

各probeにはDSLバージョンを必須とする。

```yaml
dsl_version: 1
```

将来的な互換性を維持する。

---

# 15. ValleyRAT VVAS例

既存NSEではVVASモードで、

```text
33 32 00
```

を送信し、14byteのレスポンスを受信する。

レスポンス先頭4byteをlittle endian整数として解釈し、

```text
307214
```

であること、および後続10byteがすべてNULLであることを確認している。

DSLでは以下のように記述する。

```yaml
dsl_version: 1

name: valleyrat-vvas

metadata:
  family: valleyrat
  protocol: vvas

transport:
  type: tcp
  connect_timeout_ms: 1000
  read_timeout_ms: 1000

steps:

  - send:
      hex: "33 32 00"

  - recv_exact:
      bytes: 14
      save_as: response

  - extract:
      source: response
      name: stage_size
      type: u32le
      offset: 0

  - match:
      all:

        - eq:
            left: "$stage_size"
            right: 307214

        - bytes_eq:
            source: response
            offset: 4
            hex: "00 00 00 00 00 00 00 00 00 00"

result:

  family: valleyrat
  protocol: vvas

  confirmed: "$match"

  fields:
    declared_stage_size: "$stage_size"
```

---

# 16. ValleyRAT Winos

既存NSEではWinos probeとして、

```text
header:
u32le 0x12345678
u32le 0
u16le 0x00ca
```

を生成し、`0xc9`をheader由来の値でXORしたpayloadを送信する。

応答payloadのcommandが、

```text
0xc9
0xca
0xcb
```

のいずれかの場合にmatchとしている。

DSL上では以下の演算を使用する。

```text
PACK
CONCAT
ADD
XOR
MOD
SLICE
```

固定された`valleyrat_xor`命令は作らない。

マルウェア固有処理をRust本体へ組み込まないことで、他C2へ再利用できる構造とする。

---

# 17. ValleyRAT n520

n520は他2方式と異なりserver-first型として扱う。

既存NSEではTLS接続後、クライアントからapplication dataを送信せず44byteを受信する。

その後、

```text
session_id
received_magic
CRC32
```

を検証してC2判定している。

したがってDSLで、

```yaml
transport:
  type: tls
```

および、

```yaml
- recv_exact:
    bytes: 44
```

をサポートする。

---

# 18. DSL Compile

YAMLを接続ごとにparseしてはならない。

アプリ起動時に1度だけ、

```text
probe.yaml
    │
    ▼
YAML parser
    │
    ▼
AST
    │
    ▼
Semantic Validator
    │
    ▼
IR Compiler
    │
    ▼
CompiledProbe
```

へ変換する。

---

# 19. IR例

VVASは内部的に概ね以下へ変換する。

```text
CONNECT_TCP timeout=1000

SEND_LITERAL
    33 32 00

RECV_EXACT
    14 → BUF0

READ_U32_LE
    BUF0
    OFFSET 0
    → REG0

CMP_EQ
    REG0
    307214
    → REG1

CMP_BYTES
    BUF0
    OFFSET 4
    LEN 10
    00000000000000000000
    → REG2

BOOL_AND
    REG1
    REG2
    → REG3

EMIT
```

ExecutorはYAMLについて認識しない。

---

# 20. Internal Data Type

概念的には以下。

```rust
enum Op {

    ConnectTcp {
        timeout_ms: u32,
    },

    ConnectTls {
        timeout_ms: u32,
    },

    SendLiteral {
        data: Arc<[u8]>,
    },

    RecvExact {
        length: usize,
        dst: BufferId,
    },

    ReadU32Le {
        src: BufferId,
        offset: usize,
        dst: RegisterId,
    },

    Crc32 {
        src: BufferId,
        offset: usize,
        length: usize,
        dst: RegisterId,
    },

    CompareEq {
        left: ValueRef,
        right: ValueRef,
        dst: RegisterId,
    },

    MatchBytes {
        src: BufferId,
        offset: usize,
        bytes: Arc<[u8]>,
        dst: RegisterId,
    },

    Emit {
        template: ResultTemplate,
    },
}
```

---

# 21. Probe実行戦略

open portに対して登録されたすべてのprobeを無条件で同時実行する構造にはしない。

Probe Planを定義する。

ValleyRATの場合、概念的には、

```text
open port
    │
    ▼
n520 server-first probe
    │
    ├─ confirmed
    │     ↓
    │    STOP
    │
    └─ unmatched
          │
          ▼
       winos
          │
          ├─ confirmed → STOP
          │
          ▼
        vvas
```

ただし各プロトコルで接続状態を共有できる保証がないため、

```text
probe単位で新規connection
```

を基本とする。

---

# 22. Probe Scheduler

Probe Schedulerは以下を制御する。

```text
global concurrency
per-host concurrency
per-probe concurrency
timeout
retry
```

例:

```bash
--probe-concurrency 10000
--per-host-concurrency 64
--connect-timeout 750ms
--read-timeout 1000ms
--retries 0
```

C2 fingerprint用途ではretryはデフォルト0とする。

必要な場合だけ明示的に指定する。

---

# 23. Tokio構成

Phase 2ではTokio multi-thread runtimeを使用する。

```text
Tokio Runtime
      │
      ├── worker thread
      ├── worker thread
      ├── worker thread
      └── worker thread
              │
          async tasks
              │
          thousands
          of sockets
```

OS thread数とsocket数を一致させない。

例えば、

```text
8 CPU threads
10,000 async socket operations
```

という形を基本とする。

---

# 24. Multi Process

初期実装では、

```text
processes = 1
```

をデフォルトとする。

マルチプロセスは以下の場合に利用する。

* 複数NIC
* 複数CPU NUMA node
* Lua等の将来的互換runtime
* worker isolation
* 数十万以上のconcurrency
* 1プロセスのpacket processing能力を超える場合

最初から大量processを起動する設計にはしない。

---

# 25. Queue設計

以下のqueueを使用する。

```text
TargetQueue

OpenPortQueue

ProbeQueue

ResultQueue
```

すべてbounded queueとする。

例:

```text
OpenPortQueue
capacity = 100,000

ProbeQueue
capacity = probe_concurrency × 2

ResultQueue
capacity = 100,000
```

ProducerがConsumerを上回った場合にはbackpressureを発生させる。

---

# 26. Output

デフォルトはJSONL。

理由:

* streaming可能
* 全結果をRAM保持不要
* jq等で扱いやすい
* OpenSearch投入容易
* S3/Athenaとの相性が良い

例:

```json
{
  "timestamp": "2026-08-14T13:30:00.123Z",
  "target": {
    "ip": "192.0.2.10",
    "port": 48122,
    "transport": "tcp"
  },
  "discovery": {
    "port_state": "open",
    "syn_rtt_ms": 24
  },
  "probe": {
    "name": "valleyrat-vvas",
    "family": "valleyrat",
    "protocol": "vvas",
    "confirmed": true,
    "confidence": 0.95,
    "duration_ms": 81
  },
  "fields": {
    "declared_stage_size": 307214
  }
}
```

---

# 27. CSV

CSVはflattenした結果のみ対応する。

例:

```text
timestamp
ip
port
port_state
probe
family
protocol
confirmed
confidence
status
duration_ms
```

probe固有データは、

```text
extra_json
```

カラムへJSON文字列として保存可能とする。

---

# 28. 出力フィルタ

以下を用意する。

すべて:

```bash
--output-mode all
```

open portのみ:

```bash
--output-mode open
```

probe応答あり:

```bash
--output-mode responsive
```

confirmedのみ:

```bash
--output-mode matched
```

大量探索ではデフォルトを、

```text
matched
```

または、

```text
open
```

から選択可能とする。

---

# 29. CLI案

```bash
c2probe \
  -iL targets.txt \
  -p all \
  --probe probes/valleyrat.yaml \
  --syn-rate 500000 \
  --probe-concurrency 10000 \
  --threads 8 \
  --connect-timeout 750 \
  --read-timeout 1000 \
  --log-level info \
  --log-file c2probe.log \
  --format jsonl \
  --output result.jsonl
```

単一IP:

```bash
c2probe \
  -t 192.0.2.10 \
  -p all \
  --probe probes/valleyrat.yaml
```

複数probe:

```bash
c2probe \
  -iL targets.txt \
  -p all \
  --probe-dir probes/
```

---

# 30. Scan Mode

3モード用意する。

## full

```bash
--scan-mode full
```

```text
SYN scan
↓
open port
↓
application probe
```

標準。

## discovery-only

```bash
--scan-mode discovery
```

Phase 1のみ。

## probe-only

```bash
--scan-mode probe
```

入力された、

```text
IP:PORT
```

に直接probeする。

既にShodan/Censys/OpenSearch等でopen port情報を持つ場合に利用する。

---

# 31. Known Open Port優先処理

将来的に、

```text
IP → known open ports
```

を外部データから投入可能とする。

処理順:

```text
Known open port
      │
      ▼
Immediate probe

同時に

Full SYN scan
      │
      ▼
Previously unknown open port
      │
      ▼
Probe
```

これにより既知C2候補の結果を先に取得できる。

---

# 32. Deduplication

以下を一意キーとする。

```text
IP
PORT
PROTOCOL
PROBE
```

同一スキャン内では重複probeを発生させない。

---

# 33. Timeout

Timeoutは3種類に分ける。

```text
SYN timeout

TCP connect timeout

application read timeout
```

一括timeoutにはしない。

---

# 34. Error分類

最低限以下を区別する。

```text
connection_refused

connect_timeout

read_timeout

connection_reset

tls_error

invalid_response

protocol_mismatch

probe_error

internal_error
```

単なるtimeoutをC2 negativeと同義にしない。

---

# 35. Confidence

Probe DSLからconfidenceを設定可能とする。

例えばValleyRAT:

```text
full protocol match    0.95-0.98

partial response       0.40-0.60

protocol mismatch      0.20-0.40
```

ただし最終的にはDSL側で、

```yaml
match:
  confidence: 0.95
```

のように定義可能とする。

---

# 36. Metrics

標準出力またはstatus表示用に以下を保持する。

```text
targets_total

ports_scheduled
targets_skipped
send_errors
syn_packets_sent
syn_responses
ports_open

probes_started
probes_completed
probes_matched
probes_timeout

current_syn_rate
current_probe_rate

active_connections

queue_depth

elapsed
```

Raw SYNの個別送信が失敗した場合はscan全体を停止せず、`IP:port`とOS errorを設定された
ログレベルで記録し、`targets_skipped`と`send_errors`へ計上して後続jobを継続する。
ログはstderrへ出力し、`--log-file`指定時は同じ内容をファイルへ追記する。

JSONL/CSVは各レコードを即時flushし、設定間隔ごとに`sync_data`する。discovery、probe、outputの
いずれかが失敗しても完成済みResultQueueをdrainし、出力を同期してから元のエラーを返す。

例:

```text
Targets      : 10,000
Ports        : 655,350,000
Scanned      : 320,422,310
Rate         : 487,221 pps

Open Ports   : 28,442

Probe
Active       : 8,412
Completed    : 19,002
Matched      : 7
```

---

# 37. Graceful Shutdown

Ctrl+Cを受けた場合、

```text
1. 新規job生成停止
2. sender停止
3. active probeを一定時間待機
4. ResultQueue flush
5. output close
6. summary出力
```

とする。

JSONLファイルを壊さない。

---

# 38. Resume

大量スキャンを考慮し将来的にcheckpointを実装する。

```text
scan_id
target cursor
port cursor
probe state
```

ただし初期MVPでは必須としない。

---

# 39. ディレクトリ構成

```text
c2probe/
├── Cargo.toml
├── README.md
│
├── probes/
│   ├── valleyrat/
│   │   ├── winos.yaml
│   │   ├── vvas.yaml
│   │   └── n520.yaml
│   └── ...
│
└── src/
    ├── main.rs
    │
    ├── cli/
    │   ├── mod.rs
    │   ├── args.rs
    │   └── config.rs
    │
    ├── target/
    │   ├── mod.rs
    │   ├── parser.rs
    │   ├── cidr.rs
    │   └── stream.rs
    │
    ├── discovery/
    │   ├── mod.rs
    │   ├── sender.rs
    │   ├── receiver.rs
    │   ├── packet.rs
    │   ├── correlator.rs
    │   └── rate.rs
    │
    ├── probe/
    │   ├── mod.rs
    │   ├── scheduler.rs
    │   ├── executor.rs
    │   ├── transport.rs
    │   └── matcher.rs
    │
    ├── dsl/
    │   ├── mod.rs
    │   ├── schema.rs
    │   ├── parser.rs
    │   ├── validator.rs
    │   ├── compiler.rs
    │   └── ir.rs
    │
    ├── output/
    │   ├── mod.rs
    │   ├── result.rs
    │   ├── jsonl.rs
    │   └── csv.rs
    │
    ├── metrics/
    │   └── mod.rs
    │
    └── error.rs
```

---

# 40. テスト戦略

## Unit Test

対象:

```text
CIDR expansion
port parsing
DSL parser
DSL validator
IR compiler

binary pack/unpack

XOR
CRC32

matcher
JSON serialization
```

---

# 41. Mock C2 Server

ValleyRAT各方式を模擬するローカルserverをテスト用に作る。

```text
tests/
  mock/
    valleyrat_winos.rs
    valleyrat_vvas.rs
    valleyrat_n520.rs
```

以下を再現する。

```text
正常応答

partial response

timeout

RST

invalid frame

wrong CRC

wrong magic
```

---

# 42. Differential Test

既存NSEとc2probeの結果を比較する。

```text
same mock server
     │
     ├── Nmap NSE
     │
     └── c2probe DSL
```

以下が一致することを確認する。

```text
confirmed
protocol
parsed fields
CRC
magic
command
```

ValleyRATの既存NSEをGolden Referenceとして利用する。

---

# 43. Benchmark

最低限以下を測定する。

## Phase 1

```text
SYN packets/sec

packet loss

CPU utilization

memory

open-port detection accuracy
```

## Phase 2

```text
probes/sec

connections/sec

max concurrent connections

CPU utilization

memory

timeout overhead
```

## DSL

同一probeについて、

```text
Native Rust

DSL → IR

Lua

Nmap NSE
```

を比較可能なbenchmark harnessを作る。

---

# 44. 初期性能目標

以下は保証値ではなく開発目標とする。

Phase 1:

```text
250k pps以上
```

初期安定目標。

最終的には環境条件が許せば、

```text
500k-1M pps級
```

を目標とする。

Phase 2:

```text
5,000-10,000 concurrent TCP
```

から開始。

安定後、

```text
10,000+
```

へ拡張する。

---

# 45. Linuxチューニング

大量connectionを扱うため以下を確認する。

```text
RLIMIT_NOFILE

socket buffer

ephemeral port

TIME_WAIT

NIC queue

receive buffer

CPU affinity

IRQ distribution
```

ただしOS設定変更はアプリ自身で自動実施せず、警告と推奨値表示に留める。

---

# 46. 権限

Raw SYN scanにはraw packet送受信用権限が必要となる。

root常時実行を要求するより、

```text
CAP_NET_RAW
```

等、必要最小限の権限付与を前提とする。

アプリ起動時に必要権限を確認する。

---

# 47. Safety Controls

誤操作防止として以下を持つ。

```text
--max-rate

--exclude

--exclude-file
```

有効なtargetとprobeが指定されると確認フラグなしで直ちに実行する。対象IP数、port数、
除外、設定rateの事前確認は呼び出し側の運用手順で行う。

---

# 48. 実装優先順位

実装状況（2026-08-15）:

| Phase | 状態 | 実装内容 |
|---|---|---|
| 0 | 完了 | IP/CIDR/file、port parser、CLI、JSONL/CSV |
| 1 | 完了 | Linux IPv4 Raw SYN、rate制御、SYN/ACK cookie照合 |
| 2 | 完了 | DSL core、IR compile、VVAS |
| 3 | 完了 | PACK、CONCAT、整数演算、CRC32、Winos、n520 |
| 4 | 完了 | Tokio scheduler、bounded queue、backpressure、global/host/probe concurrency、metrics |
| 5 | 完了 | sendmmsg batch、buffer再利用、CPU affinity、multi-process |

ここでの「完了」はソース実装と自動testの完了を示す。Linux Raw socketの実通信、
CPU affinity、性能目標、packet loss、Nmap NSE Differential Testは環境依存の受入試験であり、
実装状態とは分離して記録する。

## Phase 0

CLIと内部データモデル。

```text
IP
CIDR
file
port parser
JSONL
```

## Phase 1

Raw SYN scanner。

```text
IPv4
single process
rate control
open-port detection
```

## Phase 2

DSL core。

```text
SEND
RECV_EXACT
READ_U32
MATCH_BYTES
EQ
EMIT
```

VVASを最初のprobeとする。

## Phase 3

演算命令追加。

```text
PACK
CONCAT
XOR
AND
OR
SHIFT
CRC32
```

Winos/n520対応。

## Phase 4

大量concurrency。

```text
Tokio scheduler
bounded queue
backpressure
metrics
```

## Phase 5

性能最適化。

```text
packet batching
buffer reuse
zero/low allocation
CPU affinity
multi-process
```

実装状況（2026-08-15）:

- `sendmmsg(2)`による可変batch Raw SYN送信を実装
- packet、`iovec`、`mmsghdr`、route解決socketの再利用を実装
- 実行時重複排除キーを`Arc<str>`共有に変更
- Linux CPU affinityとmulti-processへのCPU集合分配を実装
- port stride sharding、全体rate/thread/concurrency分配、JSONL集約を実装

Windows上ではunit/integration testとLinux向けクロス型検査までを実施している。
Raw socket、CPU affinity、性能目標、packet lossはLinux検証hostでの受入試験が必要であり、
未検証項目として扱う。測定条件と手順は`docs/PERFORMANCE.md`を正本とする。

---

# 49. MVP完了条件

以下が成立すればMVPとする。

```text
IP単体入力
CIDR入力
ファイル入力

1-65535 TCP scan

Raw SYN port discovery

ValleyRAT VVAS
ValleyRAT Winos
ValleyRAT n520

DSL → IR compile

Tokio async probe execution

JSONL
CSV

rate指定
concurrency指定

timeout指定
```

また、

```text
Nmap valleyrat-c2.nse
```

とMock server上で同じ判定結果になることを必須とする。

---

# 50. 将来拡張

## NSE静的変換

`nse2yaml`をscannerとは別binaryとして提供する。NSEを実行せずLua token列として解析し、
対応profileのprotocol semanticsだけをDSL v1へ変換する。任意Luaの完全互換を目標としない。

変換器は次を満たすこと。

```text
unknown/dynamic module        -> reject
OS/filesystem/process API     -> reject
unknown socket method         -> reject
unexpected mode/constant/I/O  -> reject
generated YAML compile error  -> reject before output
existing output               -> reject unless --force
semantic gap                  -> conversion-report.json
```

初期profileは参照`valleyrat-c2.nse`の`winos`、`vvas`、`n520`を対象とする。VVASとN520は
core match equivalent、Winosは15 byte minimal control frameに限定したconservative subsetとする。
Winosのreflection除外と宣言長15–64はDSL v1の未対応semanticsとしてreportへ記録する。

fixtureのSHA-256、upstream license、3 rule比較、constant mutation testをsource treeへ保持し、
build packageには`nse2yaml` binaryと`docs/NSE_CONVERSION.md`を含める。

### reviewed upstream registry拡張（2026-08-17）

`analysis-framework/nmap/scripts`の12 NSEをinventory化し、application通信を持つprofileを
family別YAMLへ展開する。DNS解決だけ、およびtcp-open観測だけのNSEは、意味のないC2判定を
生成せずtarget preprocessingまたはnative discoveryへ対応付ける。

追加DSL/IR operation:

- bounded `recv_up_to`、`recv_until`、length-prefixed `recv_frame`
- bounded HTTP/1.0・HTTP/1.1 request/response（chunkedとduplicate headerは拒否）
- plaintext prelude後の同一TCP stream TLS upgrade、leaf certificate SHA-256
- ASCII-hex、Base64、RC4、gzip、限定MessagePack map string transform
- byte contains/regex、buffer length/ascii decimal、reconnect
- IP/CIDR・port scope、型と長さを検証するruntime parameter

結果は`confirmed`、`probable`、`observation`へ分離する。`matched`はconfirmedだけ、
`detected`はconfirmedとprobableを出力し、observationをC2判定へ昇格させない。全YAMLは
registry compile testを通し、代表的な新規protocolはlocal mock serverで通信vectorを検証する。
全件対応と保守的表現差は`docs/NSE_COVERAGE.md`をcanonical matrixとする。

## Probe Registry

```text
probes/
 ├── valleyrat
 ├── cobaltstrike
 ├── sliver
 ├── ...
```

のようにC2 fingerprintを追加可能にする。

## UDP

```text
UDP Discovery
UDP Probe
```

追加。

## TLS Fingerprint

```text
certificate
JA3/JA4相当情報
ALPN
TLS version
```

等を補助シグナルとして利用可能にする。

## External enrichment

```text
Shodan
Censys
OpenSearch
```

等からknown-open-portを入力するインターフェースを追加可能にする。

ただしscanner本体と外部API依存は分離する。

---

# 51. 最終的な設計原則

本ツールでは以下を厳守する。

```text
Port Discovery
        =
Rust Native Raw SYN

C2 Fingerprinting
        =
Custom DSL
        ↓
Compile Once
        ↓
IR
        ↓
Rust Executor

Network Parallelism
        =
Tokio Async I/O

CPU Parallelism
        =
Worker Threads

Scaling
        =
Optional Multi Process

Output
        =
Streaming JSONL / CSV
```

特に、

```text
65,535 ports
×
大量IP
```

に対してC2 application probeを直接実行しない。

必ず、

```text
SYN discovery
↓
OPEN
↓
C2 protocol probe
```

とする。

これによりValleyRATのように待受ポートが固定されないC2でも全ポートを網羅しながら、application-level probe数を大幅に削減できる。

またNSE互換性そのものを目的とはせず、

```text
NSE / malware analysis
        ↓
protocol semantics
        ↓
c2probe DSL
```

へ変換する方式を基本とする。

これが本ツールの中核設計とする。
