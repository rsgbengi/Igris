#!/usr/bin/env python3
from neo4j import GraphDatabase
import py2neo
import pandas as pd
import networkx as nx
import plotly.graph_objects as go
import dash
from dash import dcc
from dash import html
import dash_cytoscape as cyto
from textwrap import dedent as d
from json import dumps, loads
import base64
from dash.dependencies import Input, Output, State

images = {
    "admin": base64.b64encode(open("icons/admin.png", "rb").read()),
    "user": base64.b64encode(open("icons/usuario.png", "rb").read()),
    "computer": base64.b64encode(open("icons/ordenador.png", "rb").read()),
    "subnet": base64.b64encode(open("icons/internet.png", "rb").read()),
}


def parse_subnets(subnets, graph):
    for subnet in subnets:
        node = {
            "classes": "subnet",
            "data": {
                "id": subnet["subnet"],
                "label": subnet["subnet"],
            },
        }
        graph.append(node)


def computer_psexec_relationships(relationships, graph):

    for relation in relationships:
        user_id = (
            relation["p"].start_node["ip"]
            + relation["p"].start_node["username"]
            + relation["p"].start_node["password"]
        )
        user_node = {
            "classes": "admin",
            "data": {
                "id": user_id,
                "label": relation["p"].start_node["username"]
                + "/"
                + relation["p"].start_node["password"],
            },
        }

        graph.append(user_node)
        computer_id = relation["p"].end_node["computer_name"]
        relation = {
            "classes": "admin_arrow",
            "data": {"source": user_id, "target": computer_id},
        }
        graph.append(relation)


def computer_not_psexec_relationships(relationships, graph):
    for relation in relationships:
        user_id = (
            relation["p"].start_node["ip"]
            + relation["p"].start_node["username"]
            + relation["p"].start_node["password"]
        )
        user_node = {
            "classes": "user",
            "data": {
                "id": user_id,
                "label": relation["p"].start_node["username"]
                + "/"
                + relation["p"].start_node["password"],
            },
        }
        graph.append(user_node)

        computer_id = relation["p"].end_node["computer_name"]
        relation = {
            "classes": "user_arrow",
            "data": {
                "source": user_id,
                "target": computer_id,
            },
        }
        graph.append(relation)


def computer_part_of_relationship(relationships, graph):
    for relation in relationships:
        computer_node = {
            "classes": "computer",
            "data": {
                "id": relation["p"].start_node["computer_name"],
                "label": relation["p"].start_node["computer_name"],
            },
        }
        graph.append(computer_node)

        computer_id = relation["p"].start_node["computer_name"]
        subnet_id = relation["p"].end_node["subnet"]
        relation = {
            "classes": "computer_arrow",
            "data": {"source": computer_id, "target": subnet_id},
        }
        graph.append(relation)


def define_nodes(graph, graph_result):
    subnets = graph.nodes.match("Subnet").all()
    parse_subnets(subnets, graph_result)
    # users = graph.nodes.match("User").all()
    # parse_users(users, graph_result)
    # computers = graph.nodes.match("Computer").all()
    # parse_computers(computers, graph_result)
    return graph_result


def define_edges(graph, graph_result):
    computers_part_of = graph.run("MATCH p=()-[r:PART_OF]->() RETURN p LIMIT 25").data()
    computer_part_of_relationship(computers_part_of, graph_result)
    computers_psexec = graph.run(
        "MATCH p=()-[r:PSEXEC_HERE]->() RETURN p LIMIT 25"
    ).data()
    computer_psexec_relationships(computers_psexec, graph_result)
    computers_not_psexec = graph.run(
        "MATCH p=()-[r:NOT_PSEXEC_HERE]->() RETURN p LIMIT 25"
    ).data()
    computer_not_psexec_relationships(computers_not_psexec, graph_result)
    return graph_result


def cytoscope():
    graph = py2neo.Graph("neo4j://localhost:7687", auth=("neo4j", "islaplana56"))
    # j = dumps(graph.run(" MATCH (n)-[r]->(c) RETURN n,type(r),c").data())
    graph_result = []
    define_nodes(graph, graph_result)
    define_edges(graph, graph_result)
    return graph_result


def define_layout():
    stylesheet = [
        {"selector": "node", "style": {"content": "data(label)"}},
        {
            "selector": "edge",
            "style": {"curve-style": "bezier"},
        },
        {
            "selector": ".admin",
            "style": {
                "width": 50,
                "height": 50,
                "background-fit": "cover",
                "background-image": f'data:image/png;base64,{images["admin"].decode()}',
            },
        },
        {
            "selector": ".user",
            "style": {
                "width": 50,
                "height": 50,
                "background-fit": "cover",
                "background-image": f'data:image/png;base64,{images["user"].decode()}',
            },
        },
        {
            "selector": ".computer",
            "style": {
                "width": 50,
                "height": 50,
                "background-fit": "cover",
                "background-image": f'data:image/png;base64,{images["computer"].decode()}',
            },
        },
        {
            "selector": ".subnet",
            "style": {
                "width": 50,
                "height": 50,
                "background-fit": "cover",
                "background-image": f'data:image/png;base64,{images["subnet"].decode()}',
            },
        },
        {
            "selector": ".admin_arrow",
            "style": {
                "target-arrow-color": "red",
                "target-arrow-shape": "triangle",
                "line-color": "red",
            },
        },
        {
            "selector": ".user_arrow",
            "style": {
                "target-arrow-color": "blue",
                "target-arrow-shape": "triangle",
                "line-color": "blue",
            },
        },
        {
            "selector": ".computer_arrow",
            "style": {
                "target-arrow-color": "black",
                "target-arrow-shape": "triangle",
                "line-color": "black",
            },
        },
    ]
    app.layout = html.Div(
        [
            html.Div(
                [html.H1("Igris Graph")],
                className="row",
                style={"textAlign": "center"},
            ),
            html.Div(
                [
                    html.Button("Psexec", id="btn-psexec", n_clicks_timestamp=0),
                    html.Button(
                        "Not_Psexec", id="btn-not-psexec", n_clicks_timestamp=0
                    ),
                    html.Button("Computers", id="btn-computers", n_clicks_timestamp=0),
                ]
            ),
            # html.Div(
            #    className="eight columns",
            #    children=[dcc.Graph(id="my-graph", figure=cytoscope())],
            # ),
            html.Div(
                [
                    cyto.Cytoscape(
                        id="igris-elements",
                        layout={"name": "cose"},
                        style={"width": "100%", "height": "550px"},
                        stylesheet=stylesheet,
                        elements=cytoscope(),
                    )
                ]
            ),
        ]
    )

    @app.callback(
        Output("igris-elements", "elements"),
        Input("btn-psexec", "n_clicks_timestamp"),
        Input("btn-not-psexec", "n_clicks_timestamp"),
        Input("btn-computers", "n_clicks_timestamp"),
        State("igris-elements", "elements"),
    )
    def update_elements(psexec_count, not_psexec_count, computers_count, elements):
        if int(psexec_count) > int(not_psexec_count) and int(psexec_count) > (
            computers_count
        ):
            print("hola")
            result = []
            graph = py2neo.Graph(
                "neo4j://localhost:7687", auth=("neo4j", "islaplana56")
            )
            relation = graph.run("MATCH p=()-[r:PSEXEC_HERE]->() RETURN p").data()
            print(relation)
            computer_psexec_relationships(relation, result)
            return result
        if int(not_psexec_count) > int(psexec_count) and int(not_psexec_count) > (
            computers_count
        ):
            result = []
            graph = py2neo.Graph(
                "neo4j://localhost:7687", auth=("neo4j", "islaplana56")
            )
            relation = graph.run("MATCH p=()-[r:NOT_PSEXEC_HERE]->() RETURN p").data()
            computer_not_psexec_relationships(relation, result)
            return result
        if int(not_psexec_count) > int(psexec_count) and int(not_psexec_count) > (
            computers_count
        ):
            result = []
            graph = py2neo.Graph(
                "neo4j://localhost:7687", auth=("neo4j", "islaplana56")
            )
            relation = graph.run("MATCH p=()-[r:PART_OF]->() RETURN p").data()
            computer_part_of_relationship(relation, result)
            return result

        return elements


external_stylesheets = ["https://codepen.io/chriddyp/pen/bWLwgP.css"]
app = dash.Dash(__name__, external_stylesheets=external_stylesheets)
app.title = "Transaction Network"
if __name__ == "__main__":
    define_layout()
    app.run_server(debug=True)
