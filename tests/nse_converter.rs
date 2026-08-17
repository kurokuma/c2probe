use c2probe::{
    dsl::{ProbeDocument, compile},
    nse,
};
use serde_yaml::Value;
use std::{collections::BTreeMap, time::Duration};

const UPSTREAM_NSE: &str = include_str!("fixtures/valleyrat-c2.nse");

#[test]
fn upstream_valleyrat_nse_generates_the_three_canonical_rules() {
    let bundle = nse::convert_valleyrat(UPSTREAM_NSE).unwrap();
    assert_eq!(bundle.report.detected_modes, ["winos", "vvas", "n520"]);
    assert_eq!(bundle.probes.len(), 3);

    let canonical = BTreeMap::from([
        ("winos.yaml", include_str!("../probes/valleyrat/winos.yaml")),
        ("vvas.yaml", include_str!("../probes/valleyrat/vvas.yaml")),
        ("n520.yaml", include_str!("../probes/valleyrat/n520.yaml")),
    ]);
    for generated in &bundle.probes {
        let document: ProbeDocument = serde_yaml::from_str(&generated.yaml).unwrap();
        compile(
            document,
            Duration::from_millis(750),
            Duration::from_millis(1000),
        )
        .unwrap();

        let mut generated_value: Value = serde_yaml::from_str(&generated.yaml).unwrap();
        let mut canonical_value: Value =
            serde_yaml::from_str(canonical[generated.filename.as_str()]).unwrap();
        remove_description(&mut generated_value);
        remove_description(&mut canonical_value);
        assert_eq!(
            generated_value, canonical_value,
            "{} differs from the maintained rule",
            generated.filename
        );
    }

    let equivalence = bundle
        .report
        .generated_rules
        .iter()
        .map(|rule| (rule.mode.as_str(), rule.equivalence))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(equivalence["vvas"], "core_match_equivalent");
    assert_eq!(equivalence["n520"], "core_match_equivalent");
    assert_eq!(equivalence["winos"], "conservative_subset");
}

#[test]
fn changed_protocol_constant_is_not_silently_converted() {
    let changed = UPSTREAM_NSE.replace("307214", "307215");
    let error = nse::convert_valleyrat(&changed).unwrap_err();
    assert!(error.to_string().contains("307214"), "{error:#}");
}

fn remove_description(document: &mut Value) {
    let Value::Mapping(root) = document else {
        panic!("probe document must be a mapping");
    };
    let metadata = root
        .get_mut(Value::String("metadata".into()))
        .expect("metadata");
    let Value::Mapping(metadata) = metadata else {
        panic!("metadata must be a mapping");
    };
    metadata.remove(Value::String("description".into()));
}
