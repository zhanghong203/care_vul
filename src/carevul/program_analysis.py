from __future__ import annotations

import re
from collections import defaultdict, deque
from typing import Any, Iterable


CALL_RE = re.compile(r"\bcall\s+([A-Za-z_]\w*)", re.IGNORECASE)
IDENTIFIER_RE = re.compile(r"\b[A-Za-z_]\w*\b")
CONSTRAINT_RE = re.compile(r"(?:<=|>=|==|!=|<|>)")
SIMPLE_CONSTRAINT_RE = re.compile(r"^\s*(.+?)\s*(<=|>=|==|!=|<|>)\s*(.+?)\s*$")


SENSITIVE_APIS: dict[str, dict[str, str]] = {
    "memcpy": {"family": "bounds_numeric", "kind": "memory_write"},
    "memmove": {"family": "bounds_numeric", "kind": "memory_write"},
    "strcpy": {"family": "bounds_numeric", "kind": "memory_write"},
    "strcat": {"family": "bounds_numeric", "kind": "memory_write"},
    "sprintf": {"family": "bounds_numeric", "kind": "memory_write"},
    "snprintf": {"family": "bounds_numeric", "kind": "memory_write"},
    "gets": {"family": "bounds_numeric", "kind": "memory_write"},
    "system": {"family": "taint_injection", "kind": "command"},
    "popen": {"family": "taint_injection", "kind": "command"},
    "execl": {"family": "taint_injection", "kind": "command"},
    "execv": {"family": "taint_injection", "kind": "command"},
    "malloc": {"family": "pointer_lifetime", "kind": "allocate"},
    "calloc": {"family": "pointer_lifetime", "kind": "allocate"},
    "realloc": {"family": "pointer_lifetime", "kind": "reallocate"},
    "free": {"family": "pointer_lifetime", "kind": "release"},
    "fopen": {"family": "resource_state", "kind": "open"},
    "fclose": {"family": "resource_state", "kind": "close"},
    "pthread_mutex_lock": {"family": "resource_state", "kind": "lock"},
    "pthread_mutex_unlock": {"family": "resource_state", "kind": "unlock"},
}

API_ARGUMENT_ROLES: dict[str, dict[str, int]] = {
    "memcpy": {"destination": 0, "source": 1, "size": 2},
    "memmove": {"destination": 0, "source": 1, "size": 2},
    "strcpy": {"destination": 0, "source": 1},
    "strcat": {"destination": 0, "source": 1},
    "sprintf": {"destination": 0, "format": 1},
    "snprintf": {"destination": 0, "capacity": 1, "format": 2},
    "gets": {"destination": 0},
    "system": {"command": 0},
    "popen": {"command": 0},
    "execl": {"path": 0},
    "execv": {"path": 0},
    "malloc": {"allocation_size": 0},
    "calloc": {"element_count": 0, "element_size": 1},
    "realloc": {"object": 0, "allocation_size": 1},
    "free": {"object": 0},
    "fopen": {"path": 0, "mode": 1},
    "fclose": {"object": 0},
    "pthread_mutex_lock": {"object": 0},
    "pthread_mutex_unlock": {"object": 0},
}

GUARD_TYPES = {"If", "For", "ForCond", "While", "DoWhile", "Switch"}


def _line(coord: Any) -> int:
    if not coord:
        return -1
    parts = str(coord).split(":")
    return int(parts[-2]) if len(parts) >= 2 and parts[-2].isdigit() else -1


def _graph_index(graph: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, set[str]], dict[str, set[str]]]:
    nodes = {str(node["id"]): node for node in graph.get("nodes", []) if "id" in node}
    successors: dict[str, set[str]] = {node_id: set() for node_id in nodes}
    predecessors: dict[str, set[str]] = {node_id: set() for node_id in nodes}
    for edge in graph.get("edges", []):
        source, target = str(edge.get("from", "")), str(edge.get("to", ""))
        if source in nodes and target in nodes:
            successors[source].add(target)
            predecessors[target].add(source)
    return nodes, successors, predecessors


def _reachable(start: str, successors: dict[str, set[str]]) -> set[str]:
    if not start:
        return set()
    seen: set[str] = set()
    pending = [start]
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        pending.extend(successors.get(current, ()))
    return seen


def dominator_sets(graph: dict[str, Any], entry: str | None = None) -> dict[str, set[str]]:
    """Compute forward dominators with the standard iterative data-flow algorithm."""
    nodes, successors, predecessors = _graph_index(graph)
    if not nodes:
        return {}
    entry = entry or next((node_id for node_id, node in nodes.items() if node.get("type") == "Entry"), "")
    if entry not in nodes:
        return {}
    active = _reachable(entry, successors)
    dom = {node_id: ({node_id} if node_id == entry else set(active)) for node_id in active}
    changed = True
    while changed:
        changed = False
        for node_id in active:
            if node_id == entry:
                continue
            incoming = [dom[pred] for pred in predecessors.get(node_id, ()) if pred in active]
            updated = {node_id} | (set.intersection(*incoming) if incoming else set())
            if updated != dom[node_id]:
                dom[node_id] = updated
                changed = True
    return dom


def _with_normalized_exits(graph: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Connect terminal Return nodes to Exit for post-dominator analysis only."""
    nodes = [dict(node) for node in graph.get("nodes", [])]
    edges = [dict(edge) for edge in graph.get("edges", [])]
    exit_id = next((str(node["id"]) for node in nodes if node.get("type") == "Exit"), "")
    if not exit_id:
        exit_id = "__synthetic_exit__"
        nodes.append({"id": exit_id, "type": "Exit", "label": "synthetic EXIT", "coord": None})
    outgoing = {str(edge.get("from", "")) for edge in edges}
    for node in nodes:
        node_id = str(node.get("id", ""))
        if node_id != exit_id and (node.get("type") == "Return" or node_id not in outgoing):
            edges.append({"from": node_id, "to": exit_id, "label": "implicit_exit"})
    return {"nodes": nodes, "edges": edges}, exit_id


def postdominator_sets(graph: dict[str, Any]) -> dict[str, set[str]]:
    normalized, exit_id = _with_normalized_exits(graph)
    reversed_graph = {
        "nodes": normalized["nodes"],
        "edges": [{"from": edge["to"], "to": edge["from"]} for edge in normalized["edges"]],
    }
    return dominator_sets(reversed_graph, exit_id)


def immediate_dominators(dominators: dict[str, set[str]], root: str) -> dict[str, str]:
    """Derive immediate dominators from complete dominator sets."""
    result: dict[str, str] = {}
    for node_id, values in dominators.items():
        if node_id == root:
            continue
        strict = values - {node_id}
        if strict:
            result[node_id] = max(strict, key=lambda candidate: len(dominators.get(candidate, set())))
    return result


def control_dependencies(graph: dict[str, Any]) -> list[dict[str, str]]:
    """Compute Ferrante-style control dependencies from CFG post-dominators."""
    normalized, exit_id = _with_normalized_exits(graph)
    nodes, _, _ = _graph_index(normalized)
    postdom = postdominator_sets(normalized)
    ipdom = immediate_dominators(postdom, exit_id)
    dependencies: set[tuple[str, str, str]] = set()
    outgoing_edges: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in normalized.get("edges", []):
        outgoing_edges[str(edge.get("from", ""))].append(edge)
    for edge in normalized.get("edges", []):
        source, target = str(edge.get("from", "")), str(edge.get("to", ""))
        if not source or not target or target in postdom.get(source, set()):
            continue
        stop = ipdom.get(source)
        runner = target
        visited: set[str] = set()
        while runner and runner != stop and runner not in visited:
            visited.add(runner)
            if nodes.get(source, {}).get("type") in GUARD_TYPES:
                branch = str(edge.get("label", ""))
                labels = {str(item.get("label", "")) for item in outgoing_edges.get(source, [])}
                if not branch and nodes.get(source, {}).get("type") == "If" and "True" in labels:
                    branch = "False"
                dependencies.add((source, runner, branch))
            runner = ipdom.get(runner, "")
    return [
        {"controller": controller, "dependent": dependent, "branch": branch}
        for controller, dependent, branch in sorted(dependencies)
    ]


def backward_slice(graph: dict[str, Any], starts: Iterable[str], max_nodes: int = 64) -> dict[str, Any]:
    """Return a bounded backward DFG slice and the variables carried by its edges."""
    nodes, _, predecessors = _graph_index(graph)
    edge_vars: dict[tuple[str, str], set[str]] = defaultdict(set)
    for edge in graph.get("edges", []):
        source, target = str(edge.get("from", "")), str(edge.get("to", ""))
        if edge.get("var"):
            edge_vars[(source, target)].add(str(edge["var"]))
    selected: set[str] = set()
    variables: set[str] = set()
    queue = deque(str(start) for start in starts if str(start) in nodes)
    while queue and len(selected) < max_nodes:
        current = queue.popleft()
        if current in selected:
            continue
        selected.add(current)
        for predecessor in predecessors.get(current, ()):
            variables.update(edge_vars.get((predecessor, current), ()))
            if predecessor not in selected:
                queue.append(predecessor)
    ordered = sorted(selected, key=lambda node_id: (_line(nodes[node_id].get("coord")), node_id))
    return {
        "node_ids": ordered,
        "nodes": [
            {
                "id": node_id,
                "type": nodes[node_id].get("type", ""),
                "label": nodes[node_id].get("label", ""),
                "line": _line(nodes[node_id].get("coord")),
            }
            for node_id in ordered
        ],
        "variables": sorted(variables),
        "truncated": bool(queue),
    }


def _canonical_expression(value: Any) -> str:
    text = re.sub(r"\s+", "", str(value or ""))
    while text.startswith("(") and text.endswith(")"):
        text = text[1:-1]
    return text


def _integer(value: Any) -> int | None:
    text = re.sub(r"[uUlL]+$", "", str(value or "").strip())
    try:
        return int(text, 0)
    except ValueError:
        return None


def _ast_buffer_capacities(ast_graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    nodes = {str(node.get("id")): node for node in ast_graph.get("nodes", []) if node.get("id")}
    outgoing: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in ast_graph.get("edges", []):
        outgoing[str(edge.get("from", ""))].append(edge)
    output: dict[str, dict[str, Any]] = {}
    for node_id, node in nodes.items():
        if node.get("type") != "Decl" or not str(node.get("label", "")).startswith("Decl:"):
            continue
        name = str(node["label"]).split(":", 1)[1]
        array_edge = next(
            (edge for edge in outgoing.get(node_id, []) if nodes.get(str(edge.get("to")), {}).get("type") == "ArrayDecl"),
            None,
        )
        if not array_edge:
            continue
        array_id = str(array_edge["to"])
        dim_edge = next((edge for edge in outgoing.get(array_id, []) if edge.get("child_name") == "dim"), None)
        if not dim_edge:
            continue
        dim_node = nodes.get(str(dim_edge.get("to")), {})
        raw_dimension = str(dim_node.get("label", "")).removeprefix("Const:")
        capacity = _integer(raw_dimension)
        if capacity is None:
            continue
        descendants: set[str] = set()
        pending = [array_id]
        while pending:
            current = pending.pop()
            for edge in outgoing.get(current, []):
                target = str(edge.get("to", ""))
                if target not in descendants:
                    descendants.add(target)
                    pending.append(target)
        type_names = {
            str(name).lower()
            for descendant in descendants
            for name in nodes.get(descendant, {}).get("attributes", {}).get("names", [])
        }
        byte_sized = bool(type_names & {"char", "signed char", "unsigned char"}) or "char" in type_names
        output[name] = {
            "object": name,
            "kind": "fixed_array",
            "capacity": capacity,
            "unit": "bytes" if byte_sized else "elements",
            "element_types": sorted(type_names),
            "line": _line(node.get("coord")),
        }
    return output


def _call_name(node: dict[str, Any]) -> str | None:
    call = node.get("call") or {}
    if call.get("callee"):
        return str(call["callee"])
    match = CALL_RE.search(str(node.get("label", "")))
    return match.group(1) if match else None


def _operation(node_id: str, node: dict[str, Any], api: str, spec: dict[str, str]) -> dict[str, Any]:
    call = node.get("call") or {}
    arguments = [str(argument) for argument in call.get("arguments", [])]
    roles = {
        role: arguments[index]
        for role, index in API_ARGUMENT_ROLES.get(api, {}).items()
        if index < len(arguments)
    }
    return {
        "node_id": node_id,
        "api": api,
        "family": spec["family"],
        "kind": spec["kind"],
        "line": _line(node.get("coord")),
        "label": node.get("label", ""),
        "arguments": arguments,
        "roles": roles,
        "result": call.get("result"),
    }


def _guard_expression(label: str) -> str:
    text = str(label).strip()
    if "(" in text and text.endswith(")"):
        return text[text.find("(") + 1:-1].strip()
    return text


def _parse_constraints(label: str) -> list[dict[str, str]]:
    expression = _guard_expression(label)
    output = []
    for clause in re.split(r"\s*&&\s*", expression):
        match = SIMPLE_CONSTRAINT_RE.match(clause)
        if match:
            output.append({"left": match.group(1).strip(), "operator": match.group(2), "right": match.group(3).strip()})
    return output


def _invert_constraint(constraint: dict[str, str]) -> dict[str, str]:
    inverse = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}
    return {**constraint, "operator": inverse[constraint["operator"]]}


def _constraint(
    node: dict[str, Any],
    relevant_variables: set[str],
    branch: str = "",
) -> dict[str, Any] | None:
    label = str(node.get("label", ""))
    parsed = _parse_constraints(label)
    if node.get("type") not in GUARD_TYPES or not parsed:
        return None
    if branch.lower() == "false":
        parsed = [_invert_constraint(item) for item in parsed]
    identifiers = set(IDENTIFIER_RE.findall(label))
    return {
        "node_id": str(node.get("id", "")),
        "expression": label,
        "line": _line(node.get("coord")),
        "branch_to_sink": branch or "unknown",
        "path_constraints": parsed,
        "variables": sorted(identifiers & relevant_variables),
        "relevant": bool(identifiers & relevant_variables),
    }


def _constraint_proves_bound(
    constraint: dict[str, str],
    size_expression: str,
    destination: str,
    capacity: int,
) -> bool:
    left = _canonical_expression(constraint["left"])
    right = _canonical_expression(constraint["right"])
    size = _canonical_expression(size_expression)
    capacity_forms = {str(capacity), f"sizeof({ _canonical_expression(destination) })"}
    if left == size and right in capacity_forms and constraint["operator"] in {"<", "<="}:
        return True
    if right == size and left in capacity_forms and constraint["operator"] in {">", ">="}:
        return True
    return False


def _bounds_property(
    operation: dict[str, Any],
    guards: list[dict[str, Any]],
    capacities: dict[str, dict[str, Any]],
    analysis_mode: str,
) -> dict[str, Any] | None:
    roles = operation.get("roles", {})
    destination, size_expression = roles.get("destination"), roles.get("size")
    if not destination or not size_expression:
        return None
    capacity_info = capacities.get(_canonical_expression(destination))
    if not capacity_info:
        return {
            "name": "copy_length_within_destination_capacity",
            "state": "UNKNOWN",
            "guard_effectiveness": "UNKNOWN",
            "destination": destination,
            "copy_length": size_expression,
            "reason": "destination_capacity_unknown",
        }
    effective_guard = None
    relevant_guards = []
    for guard in guards:
        constraint = guard.get("constraint") or {}
        if constraint.get("relevant"):
            relevant_guards.append(guard)
        if not guard.get("controls_sink"):
            continue
        if any(
            _constraint_proves_bound(item, size_expression, destination, capacity_info["capacity"])
            for item in constraint.get("path_constraints", [])
        ):
            effective_guard = guard
            break
    if effective_guard:
        return {
            "name": "copy_length_within_destination_capacity",
            "state": "ESTABLISHED",
            "guard_effectiveness": "EFFECTIVE",
            "destination": destination,
            "destination_capacity": capacity_info,
            "copy_length": size_expression,
            "effective_guard": effective_guard["expression"],
            "reason": "controlling_path_constraint_proves_bound",
        }
    if analysis_mode == "precise_c":
        return {
            "name": "copy_length_within_destination_capacity",
            "state": "NOT_ESTABLISHED",
            "guard_effectiveness": "INEFFECTIVE",
            "destination": destination,
            "destination_capacity": capacity_info,
            "copy_length": size_expression,
            "reason": "relevant_guard_does_not_prove_bound" if relevant_guards else "no_relevant_controlling_guard",
        }
    return {
        "name": "copy_length_within_destination_capacity",
        "state": "UNKNOWN",
        "guard_effectiveness": "UNKNOWN",
        "destination": destination,
        "destination_capacity": capacity_info,
        "copy_length": size_expression,
        "reason": "non_precise_analysis",
    }


def _lifetime_properties(
    events: list[dict[str, Any]],
    operations: list[dict[str, Any]],
    successors: dict[str, set[str]],
) -> list[dict[str, Any]]:
    allocations: dict[str, list[dict[str, Any]]] = defaultdict(list)
    releases: dict[str, list[dict[str, Any]]] = defaultdict(list)
    properties: list[dict[str, Any]] = []
    for event in events:
        roles = event.get("roles", {})
        result = event.get("result")
        obj = result if event["kind"] in {"allocate", "reallocate", "open"} else roles.get("object")
        if not obj:
            continue
        canonical = _canonical_expression(obj)
        if event["kind"] in {"allocate", "reallocate", "open"}:
            allocations[canonical].append(event)
        elif event["kind"] in {"release", "close"}:
            releases[canonical].append(event)
            has_reaching_allocation = any(
                event["node_id"] in _reachable(allocation["node_id"], successors)
                for allocation in allocations.get(canonical, [])
            )
            if not has_reaching_allocation:
                properties.append({
                    "name": "release_matches_live_object",
                    "state": "UNKNOWN",
                    "object": obj,
                    "reason": "allocation_or_alias_not_observed",
                })
    for obj, object_releases in releases.items():
        for index, first in enumerate(object_releases):
            reachable_from_first = _reachable(first["node_id"], successors)
            for second in object_releases[index + 1:]:
                if second["node_id"] in reachable_from_first:
                    properties.append({
                        "name": "object_released_more_than_once",
                        "state": "ESTABLISHED",
                        "object": obj,
                        "first_release_line": first.get("line", -1),
                        "second_release_line": second.get("line", -1),
                        "reason": "second_release_cfg_reachable_from_first",
                    })
            uses = [
                {"api": operation.get("api"), "line": operation.get("line")}
                for operation in operations
                if operation["node_id"] in reachable_from_first
                and operation.get("kind") not in {"release", "close"}
                and any(_canonical_expression(argument) == obj for argument in operation.get("arguments", []))
            ]
            if uses:
                properties.append({
                    "name": "released_object_used_later",
                    "state": "ESTABLISHED",
                    "object": obj,
                    "uses": uses,
                    "reason": "same_expression_use_cfg_reachable_after_release",
                })
    return properties


class ProgramAnalyzer:
    """Extract compact, evidence-oriented facts from VulTriage CFG/DFG graphs."""

    def __init__(self, slice_limit: int = 64):
        self.slice_limit = slice_limit

    def analyze(
        self,
        cfg_by_function: dict[str, Any],
        dfg_by_function: dict[str, Any],
        analysis_mode: str = "unknown",
        ast_graph: dict[str, Any] | None = None,
        families: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        capacities = _ast_buffer_capacities(ast_graph or {})
        output: list[dict[str, Any]] = []
        for function in sorted(set(cfg_by_function) | set(dfg_by_function)):
            cfg = cfg_by_function.get(function, {"nodes": [], "edges": []})
            dfg = dfg_by_function.get(function, {"nodes": [], "edges": []})
            evidence = self._analyze_function(function, cfg, dfg, analysis_mode, capacities, families)
            if evidence["sensitive_operations"] or (families is None and evidence["control_dependencies"]):
                output.append(evidence)
        return output

    def _analyze_function(
        self,
        function: str,
        cfg: dict[str, Any],
        dfg: dict[str, Any],
        analysis_mode: str,
        capacities: dict[str, dict[str, Any]],
        families: set[str] | None,
    ) -> dict[str, Any]:
        cfg_nodes, cfg_successors, _ = _graph_index(cfg)
        dfg_nodes, _, _ = _graph_index(dfg)
        entry = next((node_id for node_id, node in cfg_nodes.items() if node.get("type") == "Entry"), "")
        dominators = dominator_sets(cfg, entry)
        dependencies = control_dependencies(cfg)
        controlled_by: dict[str, list[dict[str, str]]] = defaultdict(list)
        for dependency in dependencies:
            controlled_by[dependency["dependent"]].append(dependency)

        operations: list[dict[str, Any]] = []
        for node_id, node in cfg_nodes.items():
            api = _call_name(node)
            spec = SENSITIVE_APIS.get(api or "")
            if not spec or (families is not None and spec["family"] not in families):
                continue
            operations.append(_operation(node_id, node, api, spec))

        slices: list[dict[str, Any]] = []
        for operation in operations:
            if operation["kind"] in {"allocate", "reallocate", "release", "open", "close", "lock", "unlock"}:
                continue
            node_id = operation["node_id"]
            data_slice = backward_slice(dfg, [node_id], self.slice_limit) if node_id in dfg_nodes else {
                "node_ids": [], "nodes": [], "variables": [], "truncated": False,
            }
            variables = set(data_slice["variables"])
            sources = [node for node in data_slice["nodes"] if node["type"] == "Parameter"]
            guards = []
            for guard_id in sorted(dominators.get(node_id, set())):
                guard = cfg_nodes.get(guard_id)
                if not guard or guard.get("type") not in GUARD_TYPES:
                    continue
                dependencies_for_guard = [
                    item for item in controlled_by.get(node_id, []) if item["controller"] == guard_id
                ]
                branch = dependencies_for_guard[0]["branch"] if dependencies_for_guard else ""
                constraint = _constraint(guard, variables | set(operation.get("roles", {}).values()), branch)
                guards.append({
                    "node_id": guard_id,
                    "expression": guard.get("label", ""),
                    "line": _line(guard.get("coord")),
                    "dominates_sink": True,
                    "controls_sink": any(item["controller"] == guard_id for item in controlled_by.get(node_id, [])),
                    "branch_to_sink": branch or "unknown",
                    "constraint": constraint,
                })
            security_property = _bounds_property(operation, guards, capacities, analysis_mode)
            slices.append({
                "sink": operation,
                "source_parameters": sources,
                "backward_slice": data_slice,
                "guards": guards,
                "security_properties": [security_property] if security_property else [],
                "limitations": [] if node_id in dfg_nodes else ["sink_not_represented_in_dfg"],
            })

        lifetime_events = [
            operation for operation in operations
            if operation["kind"] in {"allocate", "reallocate", "release", "open", "close", "lock", "unlock"}
        ]
        lifetime_events.sort(key=lambda item: (item["line"], item["node_id"]))
        lifetime_properties = _lifetime_properties(lifetime_events, operations, cfg_successors)
        relevant_nodes = {
            operation["node_id"] for operation in operations
        } | {
            node_id for security_slice in slices for node_id in security_slice["backward_slice"]["node_ids"]
        }
        relevant_dependencies = [
            dependency for dependency in dependencies if dependency["dependent"] in relevant_nodes
        ]
        return {
            "function": function,
            "analysis_mode": analysis_mode,
            "sensitive_operations": operations,
            "security_slices": slices,
            "buffer_capacities": sorted(capacities.values(), key=lambda item: item["object"]),
            "control_dependencies": relevant_dependencies,
            "lifetime_events": lifetime_events,
            "lifetime_properties": lifetime_properties,
            "analysis_families": sorted(families) if families is not None else ["all"],
            "limitations": [] if analysis_mode == "precise_c" else ["non_precise_graphs"],
        }
