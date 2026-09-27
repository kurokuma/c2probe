https://github.com/proshiba/AI-security-analysis/tree/main/analysis-framework/nmap

ここを参照しています

## 追加したマルウェア通信ルール

`condi/registration.yaml`は、[FortiGuard LabsのCondi解析](https://www.fortinet.com/blog/threat-research/condi-ddos-botnet-spreads-via-tp-links-cve-2023-1389)
にある初回登録フレームを使う。報告された既定ID `c`で `33 66 99 01 63` を送信し、
C2からの最初の3バイトが報告されたコマンド値の部分集合に一致するか調べる。
追加コマンドやbot情報は送信せず、応答も3バイトだけ読み取る。

初回の `33 66 99` はMoobotなど他のMirai派生でも使われるため、結果は
`probable`（confidence 0.70）の「Condi互換プロトコル候補」とする。
応答コード `33 66 99` は要求との反射を誤認し得るため照合から外した。
この部分集合に一致しない場合でもCondiの不在は証明できない。実C2との照合は未実施。

`probes/valleyrat/{winos,vvas,n520}.yaml`は`nse2yaml`のstrict ValleyRAT profileと
`tests/nse_converter.rs`により、参照NSEから生成されるruleとの意味的同一性を検証します。
WinosのNSE固有差分は`docs/NSE_CONVERSION.md`を参照してください。
