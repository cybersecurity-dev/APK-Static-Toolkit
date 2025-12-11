import os
import pydot
import pygraphviz
import networkx as nx
import json

from pathlib import Path

try:
    from androguard.misc import AnalyzeAPK
    from androguard.core.analysis.analysis import DEXBasicBlock
    ANDROGUARD_BLOCK = DEXBasicBlock
except ImportError:
    AnalyzeAPK = None

def _require_androguard():
    if AnalyzeAPK is None:
        raise ImportError("Androguard is required for CFG.\nInstall with: pip install androguard")

def save_nxgraph_to_dot(graph: nx.DiGraph, out_path: Path) -> tuple[bool, Path | None]:
    print(f"save_nxgraph_to_dot() Received type: {type(graph).__name__}")
    try:
        nx.drawing.nx_agraph.write_dot(graph, out_path)
        return True, out_path
    except Exception:
        raise RuntimeError("DOT export requires pydot or pygraphviz.")

def serialize_graph_for_saving_graphml_form(G: nx.Graph) -> nx.Graph | None:
    print(f"serialize_graph_for_saving_graphml_form() Received type: {type(G).__name__}")
    
    H = G.copy()
    # Define all unsupported types we need to handle
    unsupported_types = [list, dict, ANDROGUARD_BLOCK]
    
    def serialize_data(data, element_type):
        """Converts unsupported attributes within a single attribute dictionary."""
        keys_to_convert = []
        for key, value in data.items():
            value_type = type(value)

            if value_type in unsupported_types:
                keys_to_convert.append(key)
                
                # --- Start Custom Serialization Logic ---
                if value_type is list or value_type is dict:
                    # Use JSON serialization for general Python collections
                    data[key] = json.dumps(value)
                
                elif value_type is ANDROGUARD_BLOCK:
                    try:
                        # 'name' or 'idx' is an identifier
                        block_id = getattr(value, 'name', None) or getattr(value, 'idx', None)
                        if block_id is not None:
                            data[key] = f"DEXBasicBlock:{block_id}"
                        else:
                            # Fallback to the object's string representation if no ID is found
                            data[key] = str(value)    
                    except Exception as e:
                        # Safety fallback
                        data[key] = f"Serialization_Error_{str(e)}"                     
                # --- End Custom Serialization Logic ---

        if keys_to_convert:
            print(f"Serialized {element_type} attributes: {keys_to_convert}")

    # 1. Process Node Attributes
    print("Checking (Node) Attributes...")
    for n, data in H.nodes(data=True):
        serialize_data(data, 'Node')
        
    # 2. Process Edge Attributes
    print("Checking (Edge) Attributes...")
    if H.is_multigraph():
        for u, v, k, data in H.edges(keys=True, data=True):
            serialize_data(data, 'Multi-Edge')
    else:
        for u, v, data in H.edges(data=True):
            serialize_data(data, 'Edge')
            
    return H

def save_nxgraph_to_graphml(graph_object, out_path: Path) -> tuple[bool, Path | None]:
    print(f"save_nxgraph_to_graphml Received type: {type(graph_object).__name__}")
    if not isinstance(graph_object, (nx.Graph, nx.DiGraph, nx.MultiGraph, nx.MultiDiGraph)):
        print(f"Conversion Failed: The input object is not a valid NetworkX Graph.")
        print(f"Please convert your data to an nx.Graph object first.")
        return False, None    
    try:
        nx.write_graphml(graph_object, str(out_path))
        print(f"Successfully converted graph to GraphML file: '{out_path}'")
        return True, out_path
    except Exception as e:
        try:
            print(f"An error occurred during GraphML conversion: {e}")
            # handling complex types.
            prepared_graph = serialize_graph_for_saving_graphml_form(graph_object)
            nx.write_graphml(prepared_graph, str(out_path))
            print(f"\nSuccessfully converted serialized graph to GraphML file: '{out_path}'")
            return True, out_path
        except Exception as e:
            print(f"An error occurred during GraphML conversion: {e}")
            return False, None

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