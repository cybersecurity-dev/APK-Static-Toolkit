import os
import pydot
import pygraphviz
import networkx as nx

from pathlib import Path

try:
    from androguard.misc import AnalyzeAPK
except ImportError:
    AnalyzeAPK = None

def _require_androguard():
    if AnalyzeAPK is None:
        raise ImportError("Androguard is required for CFG.\nInstall with: pip install androguard")

# -> nx.Graph | nx.DiGraph | nx.MultiGraph | nx.MultiDiGraph | None
def apk_to_cfg(apk_path: Path) -> nx.DiGraph | None:
    _require_androguard()
    #APK object, DEX objects, Analysis Object
    obj_apk, obj_dex, obj_analysis = AnalyzeAPK(apk_path)
    G = nx.DiGraph()

    for method in obj_analysis.get_methods():
        method_name = f"{method.class_name}->{method.name}{method.descriptor}"

        bb = method.basic_blocks
        if not bb:
            continue

        for block in bb.get():

            node_id = f"{method_name}_bb_{block.start}"

            # Add node with instructions
            G.add_node(node_id,
                       method=method_name,
                       start=block.start,
                       instructions=[str(ins) for ins in block.get_instructions()]
                       )

            # Connect children
            for (off, child, btype) in block.childs:

                # Child may be block or integer offset
                if hasattr(child, "start"):
                    target_offset = child.start
                else:
                    target_offset = child   # int offset fallback

                child_id = f"{method_name}_bb_{target_offset}"

                # Add edge
                G.add_edge(node_id, child_id, branch_type=btype)

    return G if len(G.nodes) > 0 else None