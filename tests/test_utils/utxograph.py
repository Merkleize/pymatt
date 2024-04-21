from typing import Dict
import networkx as nx
from bokeh.io import output_file, save
from bokeh.models import (Arrow, Segment, NormalHead, BoxZoomTool, HoverTool, Plot, Range1d,
                          ResetTool, Rect, Text, ColumnDataSource, TapTool, CustomJS, Div)
from bokeh.palettes import Spectral4
from bokeh.layouts import column

from matt.manager import ContractInstance, ContractInstanceStatus, ContractManager

NODE_WIDTH = 0.2
NODE_HEIGHT = 0.15


def instance_info(inst: ContractInstance) -> str:
    return f"""{inst.contract}
Data: {inst.data_expanded}
"""


def create_utxo_graph(manager: ContractManager, filename: str):

    # Function to calculate the intersection point
    def calculate_intersection(sx, sy, ex, ey, width, height):
        dx = ex - sx
        dy = ey - sy

        if dx == 0:  # Vertical line
            return (ex, sy + height / 2 * (-1 if ey < sy else 1))

        slope = dy / dx
        if abs(slope) * width / 2 < height / 2:
            # Intersects with left/right side
            x_offset = width / 2 * (-1 if ex < sx else 1)
            y_offset = x_offset * slope
        else:
            # Intersects with top/bottom
            y_offset = height / 2 * (-1 if ey < sy else 1)
            x_offset = y_offset / slope

        return (ex - x_offset, ey - y_offset)

    # Prepare Data

    G = nx.Graph()

    node_to_instance: Dict[int, ContractInstance] = {}

    for i, inst in enumerate(manager.instances):
        if inst.status in [ContractInstanceStatus.FUNDED, ContractInstanceStatus.SPENT]:
            G.add_node(i, label=str(inst.contract))
            node_to_instance[i] = inst

    for i, inst in enumerate(manager.instances):
        if inst.next is not None:
            for next_inst in inst.next:
                i_next = manager.instances.index(next_inst)
                G.add_edge(i, i_next)

    # Layout
    # TODO: we should find a layout that respects the "transactions", grouping together
    #       inputs of the same transaction, and positioning UTXOs left-to-right in a
    #       topological order
    pos = nx.spring_layout(G)

    min_x = min(v[0] for v in pos.values())
    max_x = max(v[0] for v in pos.values())
    min_y = min(v[1] for v in pos.values())
    max_y = max(v[1] for v in pos.values())

    # Convert position to the format bokeh uses
    x, y = zip(*pos.values())

    node_names = [node_to_instance[i].contract.__class__.__name__ for i in G.nodes()]
    node_labels = [str(node_to_instance[i].contract) for i in G.nodes()]
    node_infos = [instance_info(node_to_instance[i]) for i in G.nodes()]

    source = ColumnDataSource({
        'x': x,
        'y': y,
        'node_names': node_names,
        'node_labels': node_labels,
        'node_infos': node_infos,
    })

    # Show with Bokeh
    plot = Plot(width=1024, height=768, x_range=Range1d(min_x - NODE_WIDTH*2, max_x + NODE_WIDTH*2),
                y_range=Range1d(min_y - NODE_HEIGHT*2, max_y + NODE_HEIGHT*2))

    plot.title.text = "Contracts graph"

    node_hover_tool = HoverTool(tooltips=[("index", "@node_labels")])

    plot.add_tools(node_hover_tool, BoxZoomTool(), ResetTool())

    # Nodes as rounded rectangles
    node_glyph = Rect(width=NODE_WIDTH, height=NODE_HEIGHT,
                      fill_color=Spectral4[0], line_color=None, fill_alpha=0.7)
    plot.add_glyph(source, node_glyph)

    # Labels for the nodes
    labels = Text(x='x', y='y', text='node_names',
                  text_baseline="middle", text_align="center")
    plot.add_glyph(source, labels)

    # Create a Div to display information
    info_div = Div(width=200, height=100, sizing_mode="fixed",
                   text="Click on a node")

    # CustomJS callback to update the Div content
    callback = CustomJS(args=dict(info_div=info_div, nodes_source=source), code="""
        const info = info_div;
        const selected_node_indices = nodes_source.selected.indices;

        if (selected_node_indices.length > 0) {
            const node_index = selected_node_indices[0];
            const node_info = nodes_source.data.node_infos[node_index];
            info.text = node_info;
        } else {
            info.text = "Click on a node";
        }
    """)

    for start_node, end_node in G.edges():
        sx, sy = pos[start_node]
        ex, ey = pos[end_node]

        ix_start, iy_start = calculate_intersection(
            sx, sy, ex, ey, NODE_WIDTH, NODE_HEIGHT)
        ix_end, iy_end = calculate_intersection(
            ex, ey, sx, sy, NODE_WIDTH, NODE_HEIGHT)

        start_instance = node_to_instance[start_node]
        clause_args = f"{start_instance.spending_clause}"

        edge_source = ColumnDataSource(data={
            'x0': [ix_start],
            'y0': [iy_start],
            'x1': [ix_end],
            'y1': [iy_end],
            'edge_label': [f"{clause_args}"]
        })

        segment_glyph = Segment(x0='x0', y0='y0', x1='x1',
                                y1='y1', line_color="black", line_width=2)
        segment_renderer = plot.add_glyph(edge_source, segment_glyph)

        arrow_glyph = Arrow(end=NormalHead(fill_color="black", size=10),
                            x_start='x1', y_start='y1', x_end='x0', y_end='y0',
                            source=edge_source, line_color="black")
        plot.add_layout(arrow_glyph)

        edge_hover = HoverTool(renderers=[segment_renderer], tooltips=[
            ("Clause: ", "@edge_label")])
        plot.add_tools(edge_hover)

    tap_tool = TapTool(callback=callback)
    plot.add_tools(tap_tool)

    layout = column(plot, info_div)

    output_file(filename)
    save(layout)
