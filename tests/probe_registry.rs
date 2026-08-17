use c2probe::dsl::load_probes_with_params;
use std::{collections::HashMap, path::Path, time::Duration};

#[tokio::test]
async fn every_maintained_yaml_compiles_with_review_parameters() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let parameters = HashMap::from([
        ("darkcomet.key_base64".into(), "MTIzNDU2Nzg=".into()),
        (
            "purerat.expected_cert".into(),
            "b3ae061b0b14a89d5134c279775b8f77a42214323c6bddab07f4d81ca2fc5c57".into(),
        ),
        ("stealer.build".into(), "reviewed-build".into()),
        ("stealer.key_base64".into(), "MTIzNDU2Nzg=".into()),
        ("stealer.uid".into(), "00".repeat(16)),
        ("stealer.tag".into(), "00".repeat(16)),
        ("stealer.exp".into(), "0".into()),
        ("formbook.expected_ip".into(), "192.0.2.10".into()),
        ("vidar.expected_ip".into(), "192.0.2.11".into()),
        ("amos.nvoaagent_expected_ip".into(), "192.0.2.12".into()),
        ("amos.flwoagent_expected_ip".into(), "192.0.2.13".into()),
        (
            "amos.northernvirginiapainting_expected_ip".into(),
            "192.0.2.14".into(),
        ),
    ]);
    let probes = load_probes_with_params(
        &[],
        Some(&root.join("probes")),
        Duration::from_millis(750),
        Duration::from_millis(1000),
        &parameters,
    )
    .await
    .unwrap();

    assert_eq!(probes.len(), 24);
    let mut names = probes
        .iter()
        .map(|probe| probe.name.as_ref())
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), probes.len(), "probe names must be unique");
}

#[test]
fn upstream_inventory_has_an_explicit_c2probe_mapping() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mappings: [(&str, &[&str]); 12] = [
        (
            "agenttesla-ftp-c2.nse",
            &["probes/agenttesla/ftp-banner.yaml"],
        ),
        ("c2-dns-observe.nse", &[]),
        (
            "c2-transport-observe.nse",
            &[
                "probes/observations/server-first.yaml",
                "probes/observations/tls-certificate.yaml",
                "probes/observations/http-get.yaml",
                "probes/observations/https-get.yaml",
            ],
        ),
        (
            "darkcomet-c2.nse",
            &[
                "probes/darkcomet/raw.yaml",
                "probes/darkcomet/ascii-hex.yaml",
            ],
        ),
        (
            "dotnet-rat-c2.nse",
            &[
                "probes/dotnet-rat/asyncrat.yaml",
                "probes/dotnet-rat/venomrat.yaml",
            ],
        ),
        (
            "purerat-c2.nse",
            &[
                "probes/purerat/prelude-tls-observe.yaml",
                "probes/purerat/prelude-tls-cert.yaml",
            ],
        ),
        (
            "purerat-direct-tls.nse",
            &["probes/purerat/direct-tls-d025.yaml"],
        ),
        (
            "redline-c2.nse",
            &["probes/redline/checkconnect-production.yaml"],
        ),
        (
            "stealer-http-c2.nse",
            &[
                "probes/stealer-http/stealc.yaml",
                "probes/stealer-http/lumma.yaml",
                "probes/stealer-http/remus.yaml",
            ],
        ),
        (
            "stealer-route-c2.nse",
            &[
                "probes/stealer-route/formbook-guloader.yaml",
                "probes/stealer-route/vidar-direct.yaml",
                "probes/stealer-route/amos-nvoaagent.yaml",
                "probes/stealer-route/amos-flwoagent.yaml",
                "probes/stealer-route/amos-northernvirginiapainting.yaml",
            ],
        ),
        (
            "valleyrat-c2.nse",
            &[
                "probes/valleyrat/winos.yaml",
                "probes/valleyrat/vvas.yaml",
                "probes/valleyrat/n520.yaml",
            ],
        ),
        ("xloader-c2.nse", &[]),
    ];

    assert_eq!(mappings.len(), 12);
    for (source, files) in mappings {
        assert!(source.ends_with(".nse"));
        for file in files {
            assert!(root.join(file).is_file(), "missing mapping {file}");
        }
    }
}
