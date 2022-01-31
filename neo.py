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

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "islaplana56"))
query = """
MATCH (n)-[r]->(c) RETURN *
"""
#
results = driver.session().run(query)
#
G = nx.MultiDiGraph()
#
nodes = list(results.graph()._nodes.values())
for node in nodes:
    G.add_node(node.id, labels=node._labels, properties=node._properties)
#
rels = list(results.graph()._relationships.values())
for rel in rels:
    G.add_edge(
        rel.start_node.id,
        rel.end_node.id,
        key=rel.id,
        type=rel.type,
        properties=rel._properties,
    )


edge_x = []
edge_y = []
pos = nx.layout.shell_layout(G)
for node in G.nodes:
    G.nodes[node]["pos"] = list(pos[node])
for edge in G.edges():

    x0, y0 = G.nodes[edge[0]]["pos"]
    x1, y1 = G.nodes[edge[1]]["pos"]
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
)
edge_trace = go.Scatter(
    x=edge_x,
    y=edge_y,
    line=dict(width=0.5, color="#888"),
    hoverinfo="none",
    mode="lines",
)
node_x = []
node_y = []
for node in G.nodes():
    x, y = G.nodes[node]["pos"]
    node_x.append(x)
    node_y.append(y)

node_trace = go.Scatter(
    x=node_x,
    y=node_y,
    mode="markers",
    hoverinfo="text",
    marker=dict(
        showscale=True,
        # colorscale options
        #'Greys' | 'YlGnBu' | 'Greens' | 'YlOrRd' | 'Bluered' | 'RdBu' |
        #'Reds' | 'Blues' | 'Picnic' | 'Rainbow' | 'Portland' | 'Jet' |
        #'Hot' | 'Blackbody' | 'Earth' | 'Electric' | 'Viridis' |
        colorscale="YlGnBu",
        reversescale=True,
        color=[],
        size=10,
        colorbar=dict(
            thickness=15, title="Node Connections", xanchor="left", titleside="right"
        ),
        line_width=2,
    ),
)
node_adjacencies = []
node_text = []
for node, adjacencies in enumerate(G.adjacency()):
    node_adjacencies.append(len(adjacencies[1]))
    node_text.append("# of connections: " + str(len(adjacencies[1])))

node_trace.marker.color = node_adjacencies
node_trace.text = node_text

fig = go.Figure(
    data=[edge_trace, node_trace],
    layout=go.Layout(
        title="<br>Network graph made with Python",
        titlefont_size=16,
        showlegend=False,
        hovermode="closest",
        margin=dict(b=20, l=5, r=5, t=40),
        annotations=[
            dict(
                text="Python code: <a href='https://plotly.com/ipython-notebooks/network-graphs/'> https://plotly.com/ipython-notebooks/network-graphs/</a>",
                showarrow=False,
                xref="paper",
                yref="paper",
                x=0.005,
                y=-0.002,
            )
        ],
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
    ),
)
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
    app.run_server(debug=True)

app.layout = html.Div(
    [
        html.Div(
            [html.H1("Transaction Network Graph")],
            className="row",
            style={"textAlign": "center"},
        ),
        html.Div(
            className="eight columns",
            children=[dcc.Graph(id="my-graph", figure=fig)],
        ),
    ]
)
