use anyhow::Result;
use greentic_conformance::validate_flow_folder;
use std::{fs, path::PathBuf};

fn fixture(path: &str) -> PathBuf {
    PathBuf::from("fixtures").join("flows").join(path)
}

#[test]
fn test_messaging_flow_validates_node_types_and_routing() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let src = fixture("messaging_flow_valid.ygtc");
    let dst = temp.path().join("messaging_flow_valid.ygtc");
    fs::copy(src, &dst)?;

    let report = validate_flow_folder(temp.path().to_str().unwrap())?;
    assert!(report.flows.iter().any(|f| f.id == "messaging.flow.valid"));
    Ok(())
}

#[test]
fn test_invalid_routing_references_unknown_node() {
    let temp = tempfile::tempdir().unwrap();
    let src = fixture("flow_with_invalid_routing.ygtc");
    let dst = temp.path().join("flow_with_invalid_routing.ygtc");
    fs::copy(src, &dst).unwrap();

    let err = validate_flow_folder(temp.path().to_str().unwrap()).unwrap_err();
    assert!(
        format!("{err:#}").contains("routes to missing node"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_mcp_node_requires_tool_and_action() {
    let temp = tempfile::tempdir().unwrap();
    let src = fixture("mcp_flow_invalid.ygtc");
    let dst = temp.path().join("mcp_flow_invalid.ygtc");
    fs::copy(src, &dst).unwrap();

    let err = validate_flow_folder(temp.path().to_str().unwrap()).unwrap_err();
    assert!(
        format!("{err:#}").contains("mcp node must declare tool"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_digital_worker_flow_requires_handoff() {
    let temp = tempfile::tempdir().unwrap();
    let src = fixture("digital_worker_flow_valid.ygtc");
    let dst = temp.path().join("digital_worker_flow_valid.ygtc");
    fs::copy(src, &dst).unwrap();

    let report = validate_flow_folder(temp.path().to_str().unwrap()).unwrap();
    assert!(
        report
            .flows
            .iter()
            .any(|f| f.id == "digital.worker.flow.valid")
    );
}

#[test]
fn test_digital_worker_flow_requires_worker_id_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let src = fixture("digital_worker_flow_missing_worker_id.ygtc");
    let dst = temp
        .path()
        .join("digital_worker_flow_missing_worker_id.ygtc");
    fs::copy(src, &dst).unwrap();

    let err = validate_flow_folder(temp.path().to_str().unwrap()).unwrap_err();
    assert!(
        format!("{err:#}").contains("worker_id"),
        "unexpected error: {err:?}"
    );
}
