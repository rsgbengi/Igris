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
import dash_bootstrap_components as dbc

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


def parse_users(users, graph):
    for user in users:
        user_id = user["ip"] + user["username"] + user["password"]
        node = {
            "classes": "user",
            "data": {
                "id": user_id,
                "label": user["username"] + user["password"],
            },
        }


def parse_computers(computers, graph):
    for computer in computers:
        node = {
            "classes": "computer",
            "data": {
                "id": computer["computer_name"],
                "label": computer["computer_name"],
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


def only_psexec_users(relationship):
    graph = []
    computers_used = []
    for edge in relationship:

        computer_id = edge["p"].end_node["computer_name"]
        user_id = (
            edge["p"].start_node["ip"]
            + edge["p"].start_node["username"]
            + edge["p"].start_node["password"]
        )
        user_node = {
            "classes": "admin",
            "data": {
                "id": user_id,
                "label": edge["p"].start_node["username"]
                + "/"
                + edge["p"].start_node["password"],
            },
        }

        graph.append(user_node)

        computer_id = edge["p"].end_node["computer_name"]
        computer_node = {
            "classes": "computer",
            "data": {
                "id": computer_id,
                "label": computer_id,
            },
        }
        if computer_id not in computers_used:
            graph.append(computer_node)
            computers_used.append(computer_id)

        new_edge = {
            "classes": "admin_arrow",
            "data": {
                "source": user_id,
                "target": computer_id,
            },
        }
        graph.append(new_edge)
    return graph


def only_not_psexec_users(relationship):
    graph = []
    computers_used = []
    for edge in relationship:
        user_id = (
            edge["p"].start_node["ip"]
            + edge["p"].start_node["username"]
            + edge["p"].start_node["password"]
        )
        user_node = {
            "classes": "user",
            "data": {
                "id": user_id,
                "label": edge["p"].start_node["username"]
                + "/"
                + edge["p"].start_node["password"],
            },
        }

        graph.append(user_node)

        computer_id = edge["p"].end_node["computer_name"]
        computer_node = {
            "classes": "computer",
            "data": {
                "id": computer_id,
                "label": computer_id,
            },
        }
        if computer_id not in computers_used:
            graph.append(computer_node)
            computers_used.append(computer_id)

        new_edge = {
            "classes": "user_arrow",
            "data": {
                "source": user_id,
                "target": computer_id,
            },
        }
        graph.append(new_edge)
    return graph


def only_part_of_computer(relationship, graph_driver):
    graph = []
    subnets = graph_driver.nodes.match("Subnet").all()
    parse_subnets(subnets, graph)
    for edge in relationship:
        computer_node = {
            "classes": "computer",
            "data": {
                "id": edge["p"].start_node["computer_name"],
                "label": edge["p"].start_node["computer_name"],
            },
        }
        graph.append(computer_node)

        computer_id = edge["p"].start_node["computer_name"]
        subnet_id = edge["p"].end_node["subnet"]
        new_edge = {
            "classes": "computer_arrow",
            "data": {"source": computer_id, "target": subnet_id},
        }
        graph.append(new_edge)
    return graph


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
    app.layout = dbc.Container(
        [
            html.Div(
                [
                    html.Div(
                        children=[
                            html.P(children="🥑", className="header-emoji"),
                            html.H1(children="Igris Graph", className="bg-primary text-white p-4 mb-2 text-center"),
                        ],
                        className="header",
                    ),
                    html.Div(
                        [
                            html.Button("All", id="btn-all", n_clicks_timestamp=0),
                            html.Button(
                                "Psexec", id="btn-psexec", n_clicks_timestamp=0
                            ),
                            html.Button(
                                "Not_Psexec", id="btn-not-psexec", n_clicks_timestamp=0
                            ),
                            html.Button(
                                "Computers", id="btn-computers", n_clicks_timestamp=0
                            ),
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
        ]
    )

    @app.callback(
        Output("igris-elements", "elements"),
        Input("btn-all", "n_clicks_timestamp"),
        Input("btn-psexec", "n_clicks_timestamp"),
        Input("btn-not-psexec", "n_clicks_timestamp"),
        Input("btn-computers", "n_clicks_timestamp"),
        State("igris-elements", "elements"),
    )
    def update_elements(
        all_graph_count, psexec_count, not_psexec_count, computers_count, elements
    ):
        values = [all_graph_count, psexec_count, not_psexec_count, computers_count]
        if all_graph_count == max(values):
            return cytoscope()
        if psexec_count == max(values):
            graph_driver = py2neo.Graph(
                "neo4j://localhost:7687", auth=("neo4j", "islaplana56")
            )
            relationship = graph_driver.run(
                "MATCH p=()-[r:PSEXEC_HERE]->() RETURN p"
            ).data()
            new_graph = only_psexec_users(relationship)
            return new_graph
        if not_psexec_count == max(values):
            graph_driver = py2neo.Graph(
                "neo4j://localhost:7687", auth=("neo4j", "islaplana56")
            )
            relationship = graph_driver.run(
                "MATCH p=()-[r:NOT_PSEXEC_HERE]->() RETURN p"
            ).data()
            new_graph = only_not_psexec_users(relationship)
            return new_graph
        if computers_count == max(values):
            graph_driver = py2neo.Graph(
                "neo4j://localhost:7687", auth=("neo4j", "islaplana56")
            )
            relationship = graph_driver.run(
                "MATCH p=()-[r:PART_OF]->() RETURN p"
            ).data()
            return only_part_of_computer(relationship, graph_driver)

        return elements


app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
app.title = "Igris dashboard"
if __name__ == "__main__":
    define_layout()
    app.run_server(debug=True)
