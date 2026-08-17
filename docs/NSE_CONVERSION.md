# NSEからc2probe YAMLへの変換

## 目的と安全境界

`nse2yaml`はNSEを実行するLua runtimeではない。外部から取得したNSEをdataとしてtokenizeし、
対応済みprofileの通信と判定定数を静的に検証してから、制限付きDSL v1を生成する。

この文書はstrict自動converterであるValleyRAT profileを扱う。upstream directoryの全12本を
レビューして追加した保守対象YAMLとnative対応は`NSE_COVERAGE.md`を参照する。

NSEは任意Luaを記述できるため、完全な自動変換は安全にも意味的にも成立しない。本実装は次を
既定動作とする。

- 未対応コードを黙って省略しない
- 未知のmodule、dynamic load、OS/filesystem API、未知のsocket methodを拒否する
- 期待するmode、network operation数、protocol、frame長、magic、CRC範囲が変化したら拒否する
- 生成した全YAMLをDSL compilerで検証してから書き出す
- 既存ファイルを`--force`なしで上書きしない
- NSEとYAMLの表現差をJSON reportへ残す

## CLI

```text
nse2yaml <INPUT> [--output-dir <DIR>] [--report <FILE>] [--force]
```

| option | default | behavior |
|---|---|---|
| `<INPUT>` | required | UTF-8 NSE source。最大1 MiB |
| `-o, --output-dir` | `generated-probes` | 3 YAMLと既定reportの出力先 |
| `--report` | `<output-dir>/conversion-report.json` | equivalence/safety report path |
| `--force` | off | 既存の生成ファイルを置換する |

## 参照NSEの再現可能性

- URL: <https://github.com/proshiba/AI-security-analysis/blob/main/analysis-framework/nmap/scripts/valleyrat-c2.nse>
- 取得日: 2026-08-17
- fixture: `tests/fixtures/valleyrat-c2.nse`
- SHA-256: `708768eec241fd39013b5787af56a0ee20351e1399d65345c75862afb23e5b0f`
- upstream license: fixture内の宣言および`tests/fixtures/README.md`を参照

## 3 ruleへの対応

### VVAS

NSEの次のsemanticsを`vvas.yaml`へ変換する。

- TCP
- request `33 32 00`
- 14 byte response
- offset 0のlittle-endian u32が`307214`
- offset 4から10 byteがzero

結果は既存`probes/valleyrat/vvas.yaml`とmetadata descriptionを除いて同一であり、
`core_match_equivalent`と判定する。

### N520

NSEの次のsemanticsを`n520.yaml`へ変換する。

- TLS server-first
- 44 byte response
- session IDとreceived magicはoffset 0/4のlittle-endian u32
- high/low wordをfoldし`0xa5a50000`とORしてexpected magicを計算
- offset 40のstored CRC32と先頭40 byteのcalculated CRC32を比較

結果は既存`probes/valleyrat/n520.yaml`とmetadata descriptionを除いて同一であり、
`core_match_equivalent`と判定する。

### Winos

次のコアsemanticsを`winos.yaml`へ変換する。

- TCP
- 15 byte heartbeat frame
- header `0x12345678`, reserved `0`, type `0x00ca`
- command `0xc9`をheader byte + `0x36`でXOR
- response commandを同じ方式でdecode
- command `0xc9`、`0xca`、`0xcb`をmatch

既存`probes/valleyrat/winos.yaml`とmetadata descriptionを除いて同一になる。NSEの
reflection除外は`reject_if`と`buffer_starts_with`で表現し、request prefixがそのまま返った場合は
confidence 0、`winos_request_reflected`としてconfirmedへ進めない。宣言長15–64のうちYAMLは
`recv_exact: 15`かつdeclared length 15へ限定されるため、全体判定は偽陽性を広げない
`conservative_subset`とする。

## 自動検証

`tests/nse_converter.rs`は実fixtureをconverterへ渡し、次を検証する。

1. `action`から`winos`、`vvas`、`n520`の3 modeを検出する
2. 3 YAMLだけを生成する
3. 全生成YAMLがDSL compilerを通過する
4. metadata descriptionを除き、保守されている3 ruleとYAML構造が一致する
5. VVASのprotocol constantを変更すると変換が失敗し、silent conversionしない

実行:

```bash
cargo test --locked --test nse_converter
```

この比較はprotocol semanticsの静的・Mock server検証である。実C2へNmap NSEとc2probeを
並行実行して応答集合を比較するdifferential testは、明示的に許可されたLinux検証環境で行う。
