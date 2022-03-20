from dash import html
import dash
from dash.dependencies import Input, Output
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto
import logging
from .graph_generator import GraphGenerator
from rich import print

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


def define_the_style() -> list:
    """[function to define the style of the dashboard and the nodes of the graph]

    Returns:
        list: [style set by the function]
    """

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
        {
            "selector": ".subnet_relation",
            "style": {
                "mid-source-arrow-color": "green",
                "mid-source-arrow-shape": "diamond",
                "mid-source-arrow-fill": "hollow",
                "line-color": "green",
            },
        },
    ]


def define_logo() -> html.Img:
    """[ Function to define the logo]
    Returns:
        html.Img: [ Image with the logo ]
    """
    return html.Img(src=images["logo"], style={"width": "30%"})


def define_legend() -> dbc.ListGroup:
    """[ Function to define the legend ]

    Returns:
        dbc.ListGroup: [ List with all the node types of the graph ]
    """

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


def define_tabs() -> dbc.Tabs:
    """[ Function to define the tabs]
    Returns:
        dbc.Tabs: [ Tabs with different types of graphs]
    """
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


def define_title() -> list:
    """[Function to define the title of the page]

    Returns:
        list: [ Title of the dashboard ]
    """
    return [html.H3("Users Graph")]


def define_the_header() -> list:
    """[function to define the header]

    Returns:
        list: [ List with the corresponding columns for the title and the logo]
    """
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


def define_the_body() -> list:
    """[Function to define de body]
    Returns:
        list: [ dashboard body ]
    """
    return [
        dbc.Col(
            [
                dbc.Card(
                    [
                        dbc.CardBody(
                            [
                                html.H2("Node Information", className="display-10"),
                                html.Hr(className="my-2"),
                                html.Div(id="node-info-output"),
                            ]
                        )
                    ],
                )
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


def define_layout() -> None:
    """[ Function that will define the layout of the dashboard ]"""
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


def all_graph_tab(graph_generator: GraphGenerator) -> html.Div:
    """[Function to display the entire user graph]

    Args:
        graph_generator (GraphGenerator): [Object to generate the graph based on the established situation]

    Returns:
        html.Div: [ html object with the graph ]
    """
    return (
        html.Div(
            [
                cyto.Cytoscape(
                    id="igris-graph",
                    layout={"name": "cola"},
                    style={"width": "100%", "height": "550px"},
                    stylesheet=define_the_style(),
                    elements=graph_generator.define_all_graph(),
                )
            ]
        ),
    )


def psexec_graph_tab(graph_generator: GraphGenerator) -> html.Div:
    """[Function to show the users who are administrators in the different computers]

    Args:
        graph_generator (GraphGenerator): [Object to generate the graph based on the established situation]

    Returns:
        html.Div: [ html object with the graph ]
    """
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


def not_psexec_graph_tab(graph_generator: GraphGenerator) -> html.Div:
    """[Function to show the users who are not administrators in the different computers]

    Args:
        graph_generator (GraphGenerator): [Object to generate the graph based on the established situation]

    Returns:
        html.Div: [ html object with the graph ]
    """
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


def subnet_computer_graph_tab(graph_generator: GraphGenerator) -> html.Div:
    """[Function to show computers of a subnet]

    Args:
        graph_generator (GraphGenerator): [Object to generate the graph based on the established situation]

    Returns:
        html.Div: [ html object with the graph ]
    """
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
def render_tab_content(active_tab: str) -> html.Div:
    """[Function to load the graph based on the selected tab]

    Args:
        active_tab (str): [Tab selected ]

    Returns:
        html.Div: [ Generated Graph ]
    """
    graph_generator = GraphGenerator()
    if active_tab == "all":
        return all_graph_tab(graph_generator)
    if active_tab == "psexec":
        return psexec_graph_tab(graph_generator)
    if active_tab == "not_psexec":
        return not_psexec_graph_tab(graph_generator)
    if active_tab == "computers":
        return subnet_computer_graph_tab(graph_generator)
    return html.Div([html.P("Something went wrong ...")])


@app.callback(
    Output("node-info-output", "children"),
    Input("igris-graph", "tapNodeData"),
)
def display_node_data(data: dict):
    """[Function to show the data of the selected node ]

    Args:
        data (dict): [ clicked node data ]

    Returns:
        _type_: [ Node information ]
    """
    if data:
        accordion_item = [
            dbc.AccordionItem(
                dbc.Card(dbc.CardBody(f"{info}"), className="mb-3"),
                title=f"{key}",
            )
            for key, info in data.items()
            if key not in ["label", "id"]
        ]
        return dbc.Accordion(
            accordion_item,
            flush=True,
        )
    else:
        return html.P("Press a node to see info")


def start_dashboard(lport: str) -> None:
    """[ Function to start the dash application ]

    Args:
        lport (str): [ Port through which to display the information ]
    """
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)
    define_layout()
    try:
        app.run_server(debug=False, port=lport)
    except OSError:
        print(f"[red] The port {lport} is already in used. Exiting ... [red]")
