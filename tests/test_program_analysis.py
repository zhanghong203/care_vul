from carevul.program_analysis import (
    ProgramAnalyzer,
    backward_slice,
    control_dependencies,
    dominator_sets,
    postdominator_sets,
)


def _cfg():
    return {
        "nodes": [
            {"id": "entry", "type": "Entry", "label": "entry", "coord": None},
            {"id": "guard", "type": "If", "label": "if (len <= size)", "coord": "x.c:2:1"},
            {"id": "sink", "type": "FuncCall", "label": "call memcpy(...)", "coord": "x.c:3:1"},
            {"id": "exit", "type": "Exit", "label": "exit", "coord": None},
        ],
        "edges": [
            {"from": "entry", "to": "guard", "label": ""},
            {"from": "guard", "to": "sink", "label": "True"},
            {"from": "guard", "to": "exit", "label": "False"},
            {"from": "sink", "to": "exit", "label": ""},
        ],
    }


def _dfg():
    return {
        "nodes": [
            {"id": "param", "type": "Parameter", "label": "param: len", "coord": "x.c:1:20"},
            {"id": "size", "type": "Assignment", "label": "assign n", "coord": "x.c:2:1"},
            {"id": "sink", "type": "FuncCall", "label": "call memcpy", "coord": "x.c:3:1"},
        ],
        "edges": [
            {"from": "param", "to": "size", "var": "len"},
            {"from": "size", "to": "sink", "var": "n"},
        ],
    }


def test_dominators_and_postdominators():
    dom = dominator_sets(_cfg(), "entry")
    assert dom["sink"] == {"entry", "guard", "sink"}
    postdom = postdominator_sets(_cfg())
    assert "exit" in postdom["guard"]


def test_control_dependency_links_guard_to_sink():
    dependencies = control_dependencies(_cfg())
    assert {"controller": "guard", "dependent": "sink", "branch": "True"} in dependencies


def test_backward_slice_reaches_parameter():
    result = backward_slice(_dfg(), ["sink"])
    assert result["node_ids"] == ["param", "size", "sink"]
    assert result["variables"] == ["len", "n"]
    assert result["truncated"] is False


def test_program_analyzer_emits_guarded_security_slice():
    evidence = ProgramAnalyzer().analyze({"copy": _cfg()}, {"copy": _dfg()}, "precise_c")
    function = evidence[0]
    security_slice = function["security_slices"][0]

    assert security_slice["sink"]["api"] == "memcpy"
    assert security_slice["source_parameters"][0]["label"] == "param: len"
    assert security_slice["guards"][0]["dominates_sink"] is True
    assert security_slice["guards"][0]["controls_sink"] is True
    assert security_slice["guards"][0]["constraint"]["relevant"] is True
