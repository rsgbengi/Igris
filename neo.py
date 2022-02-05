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
from PIL import Image
from json import dumps, loads

images = {
    "admin": "http://localhost:8000/admin.png",
    "user": "http://localhost:8000/usuario.png",
    "computer": "http://localhost:8000/computadora.jpg",
    "subnet": "http://localhost:8000/internet.png",
}


def parse_subnets(subnets, graph):
    for subnet in loads(subnets):
        node = {
            "classes": "subnet",
            "data": {
                "id": subnet["subnet"],
                "label": subnet["subnet"],
            },
        }
        graph.append(node)


def parse_users(users, graph):
    for user in loads(users):
        user_id = user["ip"] + user["username"] + user["password"]
        node = {
            "data": {"id": user_id, "label": user["username"] + "/" + user["password"]}
        }
        graph.append(node)


def parse_computers(computers, graph):
    for computer in loads(computers):
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
        computer_id = relation["p"].end_node["computer_name"]
        relation = {"data": {"source": user_id, "target": computer_id}}
        graph.append(relation)


def computer_part_of_relationship(relationships, graph):
    for relation in relationships:
        computer_id = relation["p"].start_node["computer_name"]
        subnet_id = relation["p"].end_node["subnet"]
        relation = {"data": {"source": computer_id, "target": subnet_id}}
        graph.append(relation)


def define_nodes(graph, graph_result):
    subnets = dumps(graph.nodes.match("Subnet").all())
    parse_subnets(subnets, graph_result)
    users = dumps(graph.nodes.match("User").all())
    parse_users(users, graph_result)
    computers = dumps(graph.nodes.match("Computer").all())
    parse_computers(computers, graph_result)
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
    computer_psexec_relationships(computers_not_psexec, graph_result)
    return graph_result


def cytoscope():
    graph = py2neo.Graph("neo4j://localhost:7687", auth=("neo4j", "islaplana56"))
    # j = dumps(graph.run(" MATCH (n)-[r]->(c) RETURN n,type(r),c").data())
    graph_result = []
    define_nodes(graph, graph_result)
    define_edges(graph, graph_result)
    return graph_result


external_stylesheets = ["https://codepen.io/chriddyp/pen/bWLwgP.css"]
app = dash.Dash(__name__, external_stylesheets=external_stylesheets)
app.title = "Transaction Network"
if __name__ == "__main__":
    stylesheet = [
        {"selector": "node", "style": {"content": "data(label)"}},
        {
            "selector": ".admin",
            "style": {
                "width": 90,
                "height": 80,
                "background-fit": "cover",
                "background-image": images["admin"],
            },
        },
        {
            "selector": ".user",
            "style": {
                "width": 90,
                "height": 80,
                "background-fit": "cover",
                "background-image": images["user"],
            },
        },
        {
            "selector": ".computer",
            "style": {
                "width": 90,
                "height": 80,
                "background-fit": "cover",
                "background-image": images["computer"],
            },
        },
        {
            "selector": ".subnet",
            "style": {
                "width": 90,
                "height": 80,
                "background-fit": "cover",
                "background-image": images["subnet"],
            },
        },
    ]
    app.layout = html.Div(
        [
            html.Div(
                [html.H1("Transaction Network Graph")],
                className="row",
                style={"textAlign": "center"},
            ),
            # html.Div(
            #    className="eight columns",
            #    children=[dcc.Graph(id="my-graph", figure=cytoscope())],
            # ),
            html.Div(
                [
                    cyto.Cytoscape(
                        id="cytoscape-elements-basic",
                        layout={"name": "cose"},
                        style={"width": "100%", "height": "550px"},
                        stylesheet=stylesheet,
                        elements=cytoscope(),
                    )
                ]
            ),
        ]
    )
    app.run_server(debug=True)
