#!/usr/bin/env python3
from neo4j import GraphDatabase
import py2neo
import pandas as pd
import networkx as nx
import plotly.graph_objects as go
import dash
from dash import dcc
from dash import html
from textwrap import dedent as d
from PIL import Image

images = {"admin": "icons/admin.png"}

def cytoscope():
    pass
def create_graph():
    driver = GraphDatabase.driver(
        "bolt://localhost:7687", auth=("neo4j", "islaplana56")
    )
    query = """
    MATCH (n)-[r]->(c) RETURN *
    """
    results = driver.session().run(query)
    print(results)
    G = nx.MultiDiGraph()
    nodes = list(results.graph()._nodes.values())
    for node in nodes:
        G.add_node(
            node.id,
            labels=node._labels,
            properties=node._properties,
            image=images["admin"],
        )
        rels = list(results.graph()._relationships.values())
    for rel in rels:
        G.add_edge(
            rel.start_node.id,
            rel.end_node.id,
            key=rel.id,
            type=rel.type,
            properties=rel._properties,
        )

    pos = nx.layout.shell_layout(G)
    for node in G.nodes:
        G.nodes[node]["pos"] = list(pos[node])

    edge_x = []
    edge_y = []
    middle_edge_x = []
    middle_edge_y = []
    hovertext = []
    for edge in G.edges(data=True):
        hovertext.append(edge[2]["type"])
        x0, y0 = G.nodes[edge[0]]["pos"]
        x1, y1 = G.nodes[edge[1]]["pos"]
        middle_edge_x.append((x0 + x1) / 2)
        middle_edge_y.append((y0 + y1) / 2)
        edge_x.append(x0)
        edge_x.append(x1)
        edge_x.append(None)
        edge_y.append(y0)
        edge_y.append(y1)
        edge_y.append(None)

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line=dict(width=0.5, color="#888"),
        hoverinfo="none",
        mode="lines",
        line_shape="spline",
        opacity=1,
    )

    middle_hover_trace = go.Scatter(
        x=middle_edge_x,
        y=middle_edge_y,
        hovertext=hovertext,
        mode="markers",
        hoverinfo="text",
        marker={"size": 20, "color": "LightSkyBlue"},
        opacity=0,
    )

    node_x = []
    node_y = []
    hovertext = []
    text = []
    for node in G.nodes():
        x, y = G.nodes[node]["pos"]
        if "computer_name" in G.nodes[node]["properties"]:
            hovertext.append(G.nodes[node]["properties"]["ipv4"])
            text.append(G.nodes[node]["properties"]["computer_name"])
        if "username" in G.nodes[node]["properties"]:
            hovertext.append(G.nodes[node]["properties"]["ip"])
            text.append(
                G.nodes[node]["properties"]["username"]
                + "/"
                + G.nodes[node]["properties"]["password"]
            )
        if "subnet" in G.nodes[node]["properties"]:
            text.append(G.nodes[node]["properties"]["subnet"])

            hovertext.append(G.nodes[node]["properties"]["subnet"])

        node_x.append(x)
        node_y.append(y)

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        hovertext=hovertext,
        text=text,
        mode="markers+text",
        textposition="bottom center",
        hoverinfo="text",
        marker={"size": 50, "color": "LightSkyBlue"},
    )

    # node_adjacencies = []
    # node_text = []
    # for node, adjacencies in enumerate(G.adjacency()):
    #    node_adjacencies.append(len(adjacencies[1]))
    #    node_text.append("# of connections: " + str(len(adjacencies[1])))

    # node_trace.marker.color = node_adjacencies
    # node_trace.text = node_text

    fig = go.Figure(
        data=[edge_trace, node_trace, middle_hover_trace],
        layout=go.Layout(
            title="<br>Igris Graph",
            margin={"b": 40, "l": 40, "r": 40, "t": 40},
            xaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
            yaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
            height=600,
            clickmode="event+select",
            annotations=[
                dict(
                    ax=(G.nodes[edge[0]]["pos"][0] + G.nodes[edge[1]]["pos"][0]) / 2,
                    ay=(G.nodes[edge[0]]["pos"][1] + G.nodes[edge[1]]["pos"][1]) / 2,
                    axref="x",
                    ayref="y",
                    x=(G.nodes[edge[1]]["pos"][0] * 3 + G.nodes[edge[0]]["pos"][0]) / 4,
                    y=(G.nodes[edge[1]]["pos"][1] * 3 + G.nodes[edge[0]]["pos"][1]) / 4,
                    xref="x",
                    yref="y",
                    showarrow=True,
                    arrowhead=3,
                    arrowsize=4,
                    arrowwidth=1,
                    opacity=1,
                )
                for edge in G.edges()
            ],
        ),
    )
    for node in G.nodes():
        fig.add_layout_image(
            dict(
                source=Image.open("icons/admin.png"),
                xref="x",
                yref="y",
                x=G.nodes[node]["pos"][0],
                y=G.nodes[node]["pos"][1],
                sizex=0.1,
                sizey=0.1,
                sizing="contain",
                opacity=1,
                layer="above",
            )
        )
    return fig


# graph = py2neo.Graph("neo4j://localhost:7687", auth=("neo4j", "islaplana56"))
# matcher = py2neo.NodeMatcher(graph)
## df = graph.run("MATCH (n) -[r]->(c) RETURN *").data()
## print(df)
# G = nx.MultiDiGraph()
# users = matcher.match("User").all()
# for node in users:
#    print(node.identity)
#    G.add_node(node.identity, labels=node.labels, properties=node)
#
# print(G.nodes[0])
# subnets = pd.DataFrame(graph.nodes.match("Subnet").all())
# print(subnets)
# computers = pd.DataFrame(graph.nodes.match("Computer").all())
# print(computers)

external_stylesheets = ["https://codepen.io/chriddyp/pen/bWLwgP.css"]
app = dash.Dash(__name__, external_stylesheets=external_stylesheets)
app.title = "Transaction Network"
if __name__ == "__main__":
    app.layout = html.Div(
        [
            html.Div(
                [html.H1("Transaction Network Graph")],
                className="row",
                style={"textAlign": "center"},
            ),
            html.Div(
                className="eight columns",
                children=[dcc.Graph(id="my-graph", figure=cytoscope())],
            ),
        ]
    )
    app.run_server(debug=True)
