//! WebAssembly Component Model and embedded WIT analysis.

use serde::{Deserialize, Serialize};
use wit_component::WitPrinter;
use wit_parser::{
    Handle, Resolve, Type, TypeDefKind, WorldItem,
    decoding::{DecodedWasm, decode},
};

/// Maximum component size analyzed inline after upload.
pub const MAX_ANALYSIS_BYTES: u64 = 64 * 1024 * 1024;

/// A function exposed by a WIT world or interface.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct WitFunction {
    /// WIT function name.
    pub name: String,
    /// Parameter names and resolved type descriptions.
    pub params: Vec<WitParameter>,
    /// Optional result type description.
    pub result: Option<String>,
}

/// A WIT function parameter.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct WitParameter {
    /// Parameter name.
    pub name: String,
    /// Human-readable WIT type.
    pub ty: String,
}

/// One imported or exported world item.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct WitWorldItem {
    /// Canonical item name.
    pub name: String,
    /// Item category: interface, function, or type.
    pub kind: String,
    /// Functions contained by this item.
    pub functions: Vec<WitFunction>,
}

/// A dependency graph node.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct GraphNode {
    /// Stable node identifier within this graph.
    pub id: String,
    /// Display label.
    pub label: String,
    /// Node category.
    pub kind: String,
}

/// A directed dependency graph edge.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct GraphEdge {
    /// Source node identifier.
    pub from: String,
    /// Target node identifier.
    pub to: String,
    /// Relationship category.
    pub kind: String,
}

/// Component analysis persisted for an immutable blob.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ComponentAnalysis {
    /// Component blob digest.
    pub digest: String,
    /// `component` or `wit-package`.
    pub kind: String,
    /// Main WIT package identifier.
    pub package: String,
    /// Selected world name, when one is present.
    pub world: Option<String>,
    /// World imports.
    pub imports: Vec<WitWorldItem>,
    /// World exports.
    pub exports: Vec<WitWorldItem>,
    /// Canonical reconstructed WIT source.
    pub wit: String,
    /// Nodes for visualizing component dependencies.
    pub nodes: Vec<GraphNode>,
    /// Directed dependency relationships.
    pub edges: Vec<GraphEdge>,
}

/// Decode a component or binary WIT package and extract its interface graph.
pub fn analyze(digest: &str, bytes: &[u8]) -> anyhow::Result<ComponentAnalysis> {
    anyhow::ensure!(
        wasmparser::Parser::is_component(bytes),
        "binary is a core WebAssembly module, not a component"
    );
    let decoded = decode(bytes)?;
    let (kind, resolve, selected_world, package_id) = match decoded {
        DecodedWasm::Component(resolve, world) => {
            let package = resolve.worlds[world]
                .package
                .ok_or_else(|| anyhow::anyhow!("decoded component world has no package"))?;
            ("component", resolve, Some(world), package)
        }
        DecodedWasm::WitPackage(resolve, package) => {
            let world = resolve.packages[package].worlds.values().next().copied();
            ("wit-package", resolve, world, package)
        }
    };
    let package = resolve.packages[package_id].name.to_string();
    let mut printer = WitPrinter::default();
    printer.print(&resolve, package_id, &[])?;
    let wit = printer.output.to_string();

    let (world, imports, exports) = if let Some(world_id) = selected_world {
        let world = &resolve.worlds[world_id];
        (
            Some(world.name.clone()),
            collect_items(&resolve, &world.imports),
            collect_items(&resolve, &world.exports),
        )
    } else {
        (None, Vec::new(), Vec::new())
    };
    let center = "component".to_owned();
    let mut nodes = vec![GraphNode {
        id: center.clone(),
        label: world.clone().unwrap_or_else(|| package.clone()),
        kind: "component".to_owned(),
    }];
    let mut edges = Vec::new();
    for (direction, items) in [("import", &imports), ("export", &exports)] {
        for (index, item) in items.iter().enumerate() {
            let id = format!("{direction}-{index}");
            nodes.push(GraphNode {
                id: id.clone(),
                label: item.name.clone(),
                kind: direction.to_owned(),
            });
            let (from, to) = if direction == "import" {
                (id, center.clone())
            } else {
                (center.clone(), id)
            };
            edges.push(GraphEdge {
                from,
                to,
                kind: direction.to_owned(),
            });
        }
    }
    Ok(ComponentAnalysis {
        digest: digest.to_owned(),
        kind: kind.to_owned(),
        package,
        world,
        imports,
        exports,
        wit,
        nodes,
        edges,
    })
}

fn collect_items(
    resolve: &Resolve,
    items: &wit_parser::IndexMap<wit_parser::WorldKey, WorldItem>,
) -> Vec<WitWorldItem> {
    items
        .iter()
        .map(|(key, item)| match item {
            WorldItem::Interface { id, .. } => WitWorldItem {
                name: resolve.name_world_key(key),
                kind: "interface".to_owned(),
                functions: resolve.interfaces[*id]
                    .functions
                    .values()
                    .map(|value| function(resolve, value))
                    .collect(),
            },
            WorldItem::Function(value) => WitWorldItem {
                name: resolve.name_world_key(key),
                kind: "function".to_owned(),
                functions: vec![function(resolve, value)],
            },
            WorldItem::Type { id, .. } => WitWorldItem {
                name: resolve.types[*id]
                    .name
                    .clone()
                    .unwrap_or_else(|| resolve.name_world_key(key)),
                kind: "type".to_owned(),
                functions: Vec::new(),
            },
        })
        .collect()
}

fn function(resolve: &Resolve, value: &wit_parser::Function) -> WitFunction {
    WitFunction {
        name: value.name.clone(),
        params: value
            .params
            .iter()
            .map(|param| WitParameter {
                name: param.name.clone(),
                ty: type_name(resolve, &param.ty),
            })
            .collect(),
        result: value.result.as_ref().map(|ty| type_name(resolve, ty)),
    }
}

fn type_name(resolve: &Resolve, ty: &Type) -> String {
    match ty {
        Type::Id(id) => {
            let definition = &resolve.types[*id];
            if let Some(name) = &definition.name {
                return name.clone();
            }
            match &definition.kind {
                TypeDefKind::Type(inner) => type_name(resolve, inner),
                TypeDefKind::List(inner) => format!("list<{}>", type_name(resolve, inner)),
                TypeDefKind::Option(inner) => format!("option<{}>", type_name(resolve, inner)),
                TypeDefKind::Tuple(tuple) => format!(
                    "tuple<{}>",
                    tuple
                        .types
                        .iter()
                        .map(|value| type_name(resolve, value))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                TypeDefKind::Result(result) => format!(
                    "result<{}, {}>",
                    result
                        .ok
                        .as_ref()
                        .map_or_else(|| "_".to_owned(), |value| type_name(resolve, value)),
                    result
                        .err
                        .as_ref()
                        .map_or_else(|| "_".to_owned(), |value| type_name(resolve, value))
                ),
                TypeDefKind::Handle(Handle::Own(resource)) => {
                    format!("own<{}>", type_id_name(resolve, *resource))
                }
                TypeDefKind::Handle(Handle::Borrow(resource)) => {
                    format!("borrow<{}>", type_id_name(resolve, *resource))
                }
                other => other.as_str().to_owned(),
            }
        }
        primitive => format!("{primitive:?}").to_lowercase(),
    }
}

fn type_id_name(resolve: &Resolve, id: wit_parser::TypeId) -> String {
    resolve.types[id]
        .name
        .clone()
        .unwrap_or_else(|| resolve.types[id].kind.as_str().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_component_imports_exports_and_graph() {
        let bytes = wat::parse_str(
            r#"(component
                (type $greeting (func (param "name" string) (result string)))
                (import "host-greet" (func $host-greet (type $greeting)))
                (export "run" (func $host-greet))
            )"#,
        )
        .unwrap();
        let analysis = analyze(&format!("sha256:{}", "00".repeat(32)), &bytes).unwrap();
        assert_eq!(analysis.kind, "component");
        assert_eq!(analysis.imports[0].name, "host-greet");
        assert_eq!(analysis.exports[0].name, "run");
        assert_eq!(analysis.edges.len(), 2);
        assert!(analysis.wit.contains("world"));
    }

    #[test]
    fn does_not_classify_core_modules_as_components() {
        let core_module = b"\0asm\x01\0\0\0";
        assert!(analyze(&format!("sha256:{}", "00".repeat(32)), core_module).is_err());
    }
}
