#!/usr/bin/env python3
import py2neo
from dash import html
import dash
import base64
from dash.dependencies import Input, Output, State
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto
from project.utils.neo.dboperations import Neo4jConnection

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


def computer_psexec_relationships(relationships, graph):
    for edge in relationships:
        user_id, user_node = define_admin_user_node(edge["p"].start_node)
        graph.append(user_node)
        computer_id = edge["p"].end_node["computer_name"]
        new_edge = define_edge_admin_user_computer(computer_id, user_id)
        graph.append(new_edge)


def computer_not_psexec_relationships(relationships, graph):
    for edge in relationships:
        user_id, user_node = define_normal_user_node(edge["p"].start_node)
        graph.append(user_node)
        computer_id = edge["p"].end_node["computer_name"]
        new_edge = define_edge_normal_user_computer(computer_id, user_id)
        graph.append(new_edge)


def computer_part_of_relationship(relationships, graph):
    for edge in relationships:
        computer_id, computer_node = define_computer_node(edge["p"].start_node)
        graph.append(computer_node)
        new_edge = define_edge_computer_subnet(edge, computer_id)
        graph.append(new_edge)


def define_nodes(graph, graph_result):
    subnets = graph.get_subnets()
    parse_subnets(subnets, graph_result)
    return graph_result


def define_edges(graph_driver, graph_result):
    computers_part_of = graph_driver.graph_with_computers()
    computer_part_of_relationship(computers_part_of, graph_result)
    admin_users = graph_driver.graph_psexec_users()
    computer_psexec_relationships(admin_users, graph_result)
    computers_not_psexec = graph_driver.graph_not_psexec_users()
    computer_not_psexec_relationships(computers_not_psexec, graph_result)
    return graph_result


def all_graph(graph_driver):
    graph_result = []
    define_nodes(graph_driver, graph_result)
    define_edges(graph_driver, graph_result)
    return graph_result


def only_psexec_users(relationship):
    graph = []
    computers_used = []
    for edge in relationship:
        user_id, user_node = define_admin_user_node(edge["p"].start_node)
        graph.append(user_node)
        computer_id, computer_node = define_computer_node(edge["p"].end_node)
        if computer_id not in computers_used:
            graph.append(computer_node)
            computers_used.append(computer_id)
        new_edge = define_edge_admin_user_computer(computer_id, user_id)
        graph.append(new_edge)
    return graph


def define_edge_admin_user_computer(computer_id, user_id):
    return {
        "classes": "admin_arrow",
        "data": {
            "source": user_id,
            "target": computer_id,
        },
    }


def define_admin_user_node(node):
    user_id = node["ip"] + node["username"] + node["password"]
    user_node = {
        "classes": "admin",
        "data": {
            "id": user_id,
            "label": node["username"] + "/" + node["password"],
        },
    }
    return user_id, user_node


def only_not_psexec_users(relationship):
    graph = []
    computers_used = []
    for edge in relationship:
        user_id, user_node = define_normal_user_node(edge["p"].start_node)
        graph.append(user_node)
        computer_id, computer_node = define_computer_node(edge["p"].end_node)
        if computer_id not in computers_used:
            graph.append(computer_node)
            computers_used.append(computer_id)

        new_edge = define_edge_normal_user_computer(computer_id, user_id)
        graph.append(new_edge)
    return graph


def define_edge_normal_user_computer(computer_id, user_id):
    return {
        "classes": "user_arrow",
        "data": {
            "source": user_id,
            "target": computer_id,
        },
    }


def define_normal_user_node(node):
    user_id = node["ip"] + node["username"] + node["password"]
    user_node = {
        "classes": "user",
        "data": {
            "id": user_id,
            "label": node["username"] + "/" + node["password"],
        },
    }
    return user_id, user_node


def define_computer_node(node):
    computer_id = node["computer_name"]
    computer_node = {
        "classes": "computer",
        "data": {
            "id": node["computer_name"],
            "label": node["computer_name"],
            "computer_name": node["computer_name"],
            "ipv4": node["ipv4"],
            "os": node["os"],
            "signed": node["signed"],
        },
    }
    return computer_id, computer_node


def define_edge_computer_subnet(edge, computer_id):
    subnet_id = edge["p"].end_node["subnet"]
    return {
        "classes": "computer_arrow",
        "data": {"source": computer_id, "target": subnet_id},
    }


def only_part_of_computer(relationship, graph_driver):
    graph = []
    subnets = graph_driver.get_subnets()
    parse_subnets(subnets, graph)
    for edge in relationship:
        computer_id, computer_node = define_computer_node(edge["p"].start_node)
        graph.append(computer_node)
        new_edge = define_edge_computer_subnet(edge, computer_id)
        graph.append(new_edge)
    return graph


def graph_psexec_users(graph_driver):
    relationship = graph_driver.graph_psexec_users()
    new_graph = only_psexec_users(relationship)
    return new_graph


def graph_not_psexec_users(graph_driver):
    relationship = graph_driver.graph_not_psexec_users()
    new_graph = only_not_psexec_users(relationship)
    return new_graph


def graph_with_computers(graph_driver):
    relationship = graph_driver.graph_with_computers()
    new_graph = only_part_of_computer(relationship, graph_driver)
    return new_graph


def define_the_style():
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
    return stylesheet


def define_logo():
    return html.Img(
        src=f'data:image/png;base64,{images["logo"].decode()}', style={"width": "30%"}
    )


def define_legend():
    return dbc.ListGroup(
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
    )


def define_tabs():
    return dbc.Tabs(
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
    )


def define_title():
    return [html.H3("Users Graph")]


def define_the_header():
    return [
        dbc.Col(
            define_title(),
            width={"size": "auto"},
        ),
        dbc.Col(
            define_logo(),
            width={"size": "auto"},
        ),
    ]


def define_the_body():
    return [
        dbc.Col(
            [
                html.H2("Node Information", className="display-10"),
                html.Hr(className="my-2"),
                html.Div(id="node-info-output"),
            ],
            width=2,
        ),
        dbc.Col(
            [
                define_tabs(),
                html.Div(id="tab-content", className="p-4"),
            ],
            width=10,
        ),
    ]


def define_layout():
    app.layout = dbc.Container(
        [
            html.Div(
                [
                    dbc.Row(
                        define_the_header(),
                        align="center",
                        justify="center",
                    ),
                    dbc.Row(
                        [
                            dbc.Col(
                                define_legend(),
                                width="auto",
                            ),
                        ],
                        justify="center",
                    ),
                    dbc.Row(
                        define_the_body(),
                    ),
                ],
            ),
        ],
        fluid=True,
    )


def all_graph_tab(stylesheet, graph_driver):
    return (
        html.Div(
            [
                cyto.Cytoscape(
                    id="igris-graph",
                    layout={"name": "cola"},
                    style={"width": "100%", "height": "550px"},
                    stylesheet=stylesheet,
                    elements=all_graph(graph_driver),
                )
            ]
        ),
    )


def psexec_graph_tab(stylesheet, graph_driver):
    return (
        html.Div(
            [
                cyto.Cytoscape(
                    id="igris-graph",
                    layout={"name": "cola"},
                    style={"width": "100%", "height": "550px"},
                    stylesheet=stylesheet,
                    elements=graph_psexec_users(graph_driver),
                )
            ]
        ),
    )


def not_psexec_graph_tab(stylesheet, graph_driver):
    return (
        html.Div(
            [
                cyto.Cytoscape(
                    id="igris-graph",
                    layout={"name": "cola"},
                    style={"width": "100%", "height": "550px"},
                    stylesheet=stylesheet,
                    elements=graph_not_psexec_users(graph_driver),
                )
            ]
        ),
    )


def subnet_computer_graph_tab(stylesheet, graph_driver):
    return (
        html.Div(
            [
                cyto.Cytoscape(
                    id="igris-graph",
                    layout={"name": "cola"},
                    style={"width": "100%", "height": "550px"},
                    stylesheet=stylesheet,
                    elements=graph_with_computers(graph_driver),
                )
            ]
        ),
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
    stylesheet = define_the_style()
    graph_driver = Neo4jConnection(
        "neo4j://localhost:7687",
        "neo4j",
        "islaplana56",
    )
    if active_tab:
        if active_tab == "all":
            return all_graph_tab(stylesheet, graph_driver)
        if active_tab == "psexec":
            return psexec_graph_tab(stylesheet, graph_driver)
        if active_tab == "not_psexec":
            return not_psexec_graph_tab(stylesheet, graph_driver)
        if active_tab == "computers":
            return subnet_computer_graph_tab(stylesheet, graph_driver)

    return "No tab selected"


@app.callback(
    Output("node-info-output", "children"),
    Input("igris-graph", "tapNodeData"),
)
def displayTapNodeData(data):
    if data:
        return html.P(data["ipv4"])
    else:
        return html.P("Press a node to see info")


if __name__ == "__main__":

    define_layout()
    app.run_server(debug=True)
