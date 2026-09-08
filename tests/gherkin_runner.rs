#[path = "integration/gherkin/steps/step_impl.rs"]
mod step_impl;

use std::fs;

fn parse_feature(path: &str) -> Vec<(String, Vec<String>)> {
    let raw = fs::read_to_string(path).expect("feature file should exist");
    let mut scenarios: Vec<(String, Vec<String>)> = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_steps: Vec<String> = Vec::new();

    for line in raw.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Some(name) = line.strip_prefix("Scenario:") {
            if let Some(existing) = current_name.take() {
                scenarios.push((existing, current_steps));
                current_steps = Vec::new();
            }
            current_name = Some(name.trim().to_string());
            continue;
        }

        for prefix in ["Given ", "When ", "Then ", "And "] {
            if let Some(step) = line.strip_prefix(prefix) {
                current_steps.push(step.trim().to_string());
                break;
            }
        }
    }

    if let Some(existing) = current_name {
        scenarios.push((existing, current_steps));
    }

    scenarios
}

#[test]
fn gherkin_api_contract_campaign() {
    let scenarios = parse_feature("tests/integration/gherkin/features/api_contract.feature");
    assert!(!scenarios.is_empty(), "feature must contain scenarios");

    for (name, steps) in scenarios {
        let mut ctx = step_impl::Context::new();
        for step in steps {
            step_impl::execute_step(&step, &mut ctx);
        }
        assert!(!name.is_empty(), "scenario name should not be empty");
    }
}
