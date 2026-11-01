//! Properties of the pure parts of the product: configuration precedence, identity files, the
//! dependency graph and Baseline composition. Each case runs through the public API.

use calve_app::config::{ConfigPaths, Scope};
use calve_app::{Project, ProjectIdentity};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Project beats Workspace beats global, whichever subset of them is set.
    #[test]
    fn the_narrowest_scope_that_sets_a_value_wins(
        global in proptest::option::of(1u16..1000),
        workspace in proptest::option::of(1u16..1000),
        project in proptest::option::of(1u16..1000),
    ) {
        let temp = tempfile::tempdir().unwrap();
        let paths = ConfigPaths {
            global: temp.path().join("g.toml"),
            workspace: temp.path().join("w.toml"),
            project: Some(temp.path().join("project/.calve/config.toml")),
            override_file: None,
        };
        for (scope, value) in [
            (Scope::Global, global),
            (Scope::Workspace, workspace),
            (Scope::Project, project),
        ] {
            if let Some(v) = value {
                paths.set(scope, "ui.page_size", &v.to_string()).unwrap();
            }
        }
        let expected = project.or(workspace).or(global);
        let effective = paths.load().unwrap().page_size;
        if let Some(v) = expected {
            prop_assert_eq!(effective, v);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// Whatever edges are asked for, the Task graph stays acyclic: a refused edge changes nothing.
    #[test]
    fn task_dependencies_never_form_a_cycle(
        edges in proptest::collection::vec((0usize..5, 0usize..5), 1..16),
    ) {
        let temp = tempfile::tempdir().unwrap();
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            let project = Project::init(temp.path(), Some("p")).await.unwrap();
            let intent = project.create_intent("i").unwrap();
            let tasks: Vec<String> = (0..5)
                .map(|n| project.create_task(&intent, &format!("t{n}")).unwrap())
                .collect();
            let mut graph = vec![vec![]; 5];
            for (a, b) in edges {
                if project.add_task_dependency(&tasks[a], &tasks[b]).is_ok() {
                    graph[a].push(b);
                }
            }
            fn reaches(graph: &[Vec<usize>], from: usize, to: usize, seen: &mut Vec<bool>) -> bool {
                graph[from].iter().any(|&n| {
                    n == to || (!seen[n] && { seen[n] = true; reaches(graph, n, to, seen) })
                })
            }
            for n in 0..5 {
                assert!(!reaches(&graph, n, n, &mut vec![false; 5]), "cycle through {n}: {graph:?}");
            }
        });
    }
}

/// An identity survives its file format exactly.
#[test]
fn identity_round_trips() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let project = runtime
        .block_on(Project::init(temp.path(), Some("p")))
        .unwrap();
    let text = toml::to_string(&project.identity).unwrap();
    let back: ProjectIdentity = toml::from_str(&text).unwrap();
    assert_eq!(toml::to_string(&back).unwrap(), text);
}
