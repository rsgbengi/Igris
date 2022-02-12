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

cyto.load_extra_layouts()
images = {
    "admin": base64.b64encode(open("icons/admin.png", "rb").read()),
    "user": base64.b64encode(open("icons/usuario.png", "rb").read()),
    "computer": base64.b64encode(open("icons/ordenador.png", "rb").read()),
    "subnet": base64.b64encode(open("icons/internet.png", "rb").read()),
    "logo": base64.b64encode(open("icons/logo.png", "rb").read()),
}
app = dash.Dash(
    __name__, external_stylesheets=[dbc.themes.BOOTSTRAP, dbc.icons.BOOTSTRAP]
)
app.title = "Igris dashboard"


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


def graph_psexec_users():
    graph_driver = py2neo.Graph("neo4j://localhost:7687", auth=("neo4j", "islaplana56"))
    relationship = graph_driver.run("MATCH p=()-[r:PSEXEC_HERE]->() RETURN p").data()
    new_graph = only_psexec_users(relationship)
    return new_graph


def graph_not_psexec_users():
    graph_driver = py2neo.Graph("neo4j://localhost:7687", auth=("neo4j", "islaplana56"))
    relationship = graph_driver.run(
        "MATCH p=()-[r:NOT_PSEXEC_HERE]->() RETURN p"
    ).data()
    new_graph = only_not_psexec_users(relationship)
    return new_graph


def graph_with_computers():
    graph_driver = py2neo.Graph("neo4j://localhost:7687", auth=("neo4j", "islaplana56"))
    relationship = graph_driver.run("MATCH p=()-[r:PART_OF]->() RETURN p").data()
    return only_part_of_computer(relationship, graph_driver)


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
                    dbc.Card(
                        [
                            dbc.Row(
                                [
                                    dbc.Col(
                                        dbc.CardImg(
                                            src=f'data:image/png;base64,{images["logo"].decode()}',
                                            className="img-fluid rounded-start",
                                        ),
                                        style={"width": "5rem"},
                                        className="col-md-4",
                                    ),
                                    dbc.Col(
                                        [
                                            dbc.CardBody(
                                                [
                                                    html.H4(
                                                        "Card title",
                                                        className="card-title",
                                                    ),
                                                    html.P(
                                                        "This is some card text",
                                                        className="card-text",
                                                    ),
                                                ]
                                            ),
                                        ]
                                    ),
                                ],
                                className="g-0 d-flex align-items-center",
                            ),
                        ],
                    ),
                    dbc.Row(
                        [
                            dbc.Col(
                                [
                                    dbc.ListGroup(
                                        [
                                            dbc.ListGroupItem(
                                                [
                                                    html.I(
                                                        className="bi bi-arrow-right-circle-fill",
                                                        style={"color": "#c93412"},
                                                    ),
                                                    "  Psexec Here",
                                                ],
                                            ),
                                            dbc.ListGroupItem(
                                                [
                                                    html.I(
                                                        className="bi bi-arrow-right-circle-fill",
                                                        style={"color": "blue"},
                                                    ),
                                                    "  Not Psexec Here",
                                                ],
                                            ),
                                            dbc.ListGroupItem(
                                                [
                                                    html.I(
                                                        className="bi bi-arrow-right-circle-fill",
                                                        style={"color": "#383534"},
                                                    ),
                                                    "  Part of the subnet",
                                                ],
                                            ),
                                            dbc.ListGroupItem(
                                                [
                                                    html.Img(
                                                        src=f'data:image/png;base64,{images["user"].decode()}',
                                                        height="20px",
                                                    ),
                                                    "  Normal User",
                                                ],
                                            ),
                                            dbc.ListGroupItem(
                                                [
                                                    html.Img(
                                                        src=f'data:image/png;base64,{images["admin"].decode()}',
                                                        height="20px",
                                                    ),
                                                    "  Administrator User",
                                                ],
                                            ),
                                            dbc.ListGroupItem(
                                                [
                                                    html.Img(
                                                        src=f'data:image/png;base64,{images["computer"].decode()}',
                                                        height="20px",
                                                    ),
                                                    "  Workstation",
                                                ],
                                            ),
                                            dbc.ListGroupItem(
                                                [
                                                    html.Img(
                                                        src=f'data:image/png;base64,{images["subnet"].decode()}',
                                                        height="20px",
                                                    ),
                                                    "  Subnet",
                                                ],
                                            ),
                                        ],
                                        horizontal=True,
                                        flush=True,
                                    ),
                                ],
                                width="auto",
                            ),
                        ],
                        justify="center",
                    ),
                    dbc.Row(
                        [
                            dbc.Tabs(
                                [
                                    dbc.Tab(
                                        label="All Graph",
                                        tab_id="all",
                                    ),
                                    dbc.Tab(
                                        label="Psexec",
                                        tab_id="psexec",
                                    ),
                                    dbc.Tab(
                                        label="Not Psexec",
                                        tab_id="not_psexec",
                                    ),
                                    dbc.Tab(
                                        label="Computers",
                                        tab_id="computers",
                                    ),
                                ],
                                id="tabs",
                                active_tab="all",
                            ),
                            html.Div(id="tab-content", className="p-4"),
                        ],
                    ),
                ],
            ),
        ],
        fluid=True,
    )

    @app.callback(
        Output("tab-content", "children"),
        [Input("tabs", "active_tab")],
    )
    def render_tab_content(active_tab):
        """
        This callback takes the 'active_tab' property as input, as well as the
        stored graphs, and renders the tab content depending on what the value of
        'active_tab' is.
        """
        if active_tab:
            if active_tab == "all":
                return (
                    html.Div(
                        [
                            cyto.Cytoscape(
                                layout={"name": "cola"},
                                style={"width": "100%", "height": "550px"},
                                stylesheet=stylesheet,
                                elements=cytoscope(),
                            )
                        ]
                    ),
                )
            if active_tab == "psexec":
                return (
                    html.Div(
                        [
                            cyto.Cytoscape(
                                layout={"name": "cola"},
                                style={"width": "100%", "height": "550px"},
                                stylesheet=stylesheet,
                                elements=graph_psexec_users(),
                            )
                        ]
                    ),
                )
            if active_tab == "not_psexec":
                return (
                    html.Div(
                        [
                            cyto.Cytoscape(
                                layout={"name": "cola"},
                                style={"width": "100%", "height": "550px"},
                                stylesheet=stylesheet,
                                elements=graph_not_psexec_users(),
                            )
                        ]
                    ),
                )
            if active_tab == "computers":
                return (
                    html.Div(
                        [
                            cyto.Cytoscape(
                                layout={"name": "cola"},
                                style={"width": "100%", "height": "550px"},
                                stylesheet=stylesheet,
                                elements=graph_with_computers(),
                            )
                        ]
                    ),
                )

        return "No tab selected"


if __name__ == "__main__":
    define_layout()
    app.run_server(debug=True)
