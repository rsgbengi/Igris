from dash import html
import dash
from dash.dependencies import Input, Output
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto
import logging
from .graph_generator import GraphGenerator

images = {
    "admin": "assets/admin.png",
    "user": "assets/usuario.png",
    "computer": "assets/ordenador.png",
    "subnet": "assets/internet.png",
    "logo": "assets/logo.png",
}
cyto.load_extra_layouts()
app = dash.Dash(
    __name__, external_stylesheets=[dbc.themes.BOOTSTRAP, dbc.icons.BOOTSTRAP]
)
app.title = "Igris dashboard"


def define_the_style():
    return [
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
                "background-image": images["admin"],
            },
        },
        {
            "selector": ".user",
            "style": {
                "width": 50,
                "height": 50,
                "background-fit": "cover",
                "background-image": images["user"],
            },
        },
        {
            "selector": ".computer",
            "style": {
                "width": 50,
                "height": 50,
                "background-fit": "cover",
                "background-image": images["computer"],
            },
        },
        {
            "selector": ".subnet",
            "style": {
                "width": 50,
                "height": 50,
                "background-fit": "cover",
                "background-image": images["subnet"],
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


def define_logo():
    return html.Img(src=images["logo"], style={"width": "30%"})


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
                        src=images["user"],
                        height="20px",
                    ),
                    "  Normal User",
                ],
            ),
            dbc.ListGroupItem(
                [
                    html.Img(
                        src=images["admin"],
                        height="20px",
                    ),
                    "  Administrator User",
                ],
            ),
            dbc.ListGroupItem(
                [
                    html.Img(
                        src=images["computer"],
                        height="20px",
                    ),
                    "  Workstation",
                ],
            ),
            dbc.ListGroupItem(
                [
                    html.Img(
                        src=images["subnet"],
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


def all_graph_tab(graph_generator):
    print("holaaaaaa")
    return (
        html.Div(
            [
                cyto.Cytoscape(
                    id="igris-graph",
                    layout={"name": "cola"},
                    style={"width": "100%", "height": "550px"},
                    stylesheet=define_the_style(),
                    elements=graph_generator.all_graph(),
                )
            ]
        ),
    )


def psexec_graph_tab(graph_generator):
    return (
        html.Div(
            [
                cyto.Cytoscape(
                    id="igris-graph",
                    layout={"name": "cola"},
                    style={"width": "100%", "height": "550px"},
                    stylesheet=define_the_style(),
                    elements=graph_generator.graph_psexec_users(),
                )
            ]
        ),
    )


def not_psexec_graph_tab(graph_generator):
    return (
        html.Div(
            [
                cyto.Cytoscape(
                    id="igris-graph",
                    layout={"name": "cola"},
                    style={"width": "100%", "height": "550px"},
                    stylesheet=define_the_style(),
                    elements=graph_generator.graph_not_psexec_users(),
                )
            ]
        ),
    )


def subnet_computer_graph_tab(graph_generator):
    return (
        html.Div(
            [
                cyto.Cytoscape(
                    id="igris-graph",
                    layout={"name": "cola"},
                    style={"width": "100%", "height": "550px"},
                    stylesheet=define_the_style(),
                    elements=graph_generator.graph_with_computers(),
                )
            ]
        ),
    )


@app.callback(
    Output("tab-content", "children"),
    [Input("tabs", "active_tab")],
)
def render_tab_content(active_tab):
    graph_generator = GraphGenerator()
    if active_tab:
        if active_tab == "all":
            return all_graph_tab(graph_generator)
        if active_tab == "psexec":
            return psexec_graph_tab(graph_generator)
        if active_tab == "not_psexec":
            return not_psexec_graph_tab(graph_generator)
        if active_tab == "computers":
            return subnet_computer_graph_tab(graph_generator)
    return "No tab selected"


@app.callback(
    Output("node-info-output", "children"),
    Input("igris-graph", "tapNodeData"),
)
def display_node_data(data):
    if data:
        return [
            dbc.Row(
                [
                    dbc.Col(html.P(f"{key}:", style={"font-weight": "bold"})),
                    dbc.Col(html.P(f"{info}")),
                ]
            )
            for key, info in data.items()
            if key not in ["label", "id"]
        ]
    else:
        return html.P("Press a node to see info")


def start_dashboard(lport: str) -> None:
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)
    define_layout()
    app.run_server(debug=False, port=lport)
