from typing import Tuple
from ...neo import Neo4jConnection
from py2neo import Node


class GraphGenerator:
    """Class to generate the different dashboard graphs."""

    def __init__(self) -> None:
        self.__graph_driver = Neo4jConnection(
            "neo4j://localhost:7687",
            "neo4j",
            "igris",
        )

    def __parse_subnets_all_graph(self, subnets: list, graph: list) -> None:
        """Method to generate the "subnet" nodes along with their edged to other subnet nodes.

        Args:
            subnets (list): subnet nodes formed as a result of the database query.
            graph (list): list with the nodes that will later form the graph using cytoscape.
        """
        nodes_to_relate = []
        for i, subnet in enumerate(subnets):
            node = {
                "classes": "subnet",
                "data": {
                    "id": subnet["subnet"],
                    "label": subnet["subnet"],
                    "subnet": subnet["subnet"],
                },
            }
            graph.append(node)
            nodes_to_relate.append(subnet["subnet"])
            if i != 0:
                new_edge = self.__subnets_relationship(
                    subnet["subnet"], nodes_to_relate[i - 1]
                )
                graph.append(new_edge)

    def __subnets_relationship(
        self, first_subnet_id: str, second_subnet_id: str
    ) -> dict:
        """Method to create the relationship between two subnet nodes.

        Args:
            first_subnet_id (str): Subnet corresponding to the first node.
            second_subnet_id (str): Subnet corresponding to the second node.

        Returns:
            dict: The edge generated.
        """
        return {
            "classes": "subnet_relation",
            "data": {
                "source": first_subnet_id,
                "target": second_subnet_id,
            },
        }

    def __computer_psexec_relationships(self, relationships: list, graph: list) -> None:
        """Method to establish the relationship between a computer node and a user node that is an administrator.

        Args:
            relationships (list): database query-based relationships.
            graph (list): list with the nodes that will later form the graph using cytoscape.
        """
        for edge in relationships:
            user_id, user_node = self.__define_admin_user_node(edge["p"].start_node)
            graph.append(user_node)
            computer_id = edge["p"].end_node["computer_name"]
            new_edge = self.__define_edge_admin_user_computer(computer_id, user_id)
            graph.append(new_edge)

    def __computer_not_psexec_relationships(
        self, relationships: list, graph: list
    ) -> None:
        """Method to establish the relationship between a computer node and and a non-admin user.
        Args:
            relationships (list): database query-based relationships.
            graph (list): list with the nodes that will later form the graph using cytoscape.
        """
        for edge in relationships:
            user_id, user_node = self.__define_normal_user_node(edge["p"].start_node)
            graph.append(user_node)
            computer_id = edge["p"].end_node["computer_name"]
            new_edge = self.__define_edge_normal_user_computer(computer_id, user_id)
            graph.append(new_edge)

    def __computer_part_of_relationship(self, relationships: list, graph: list) -> None:
        """Method to establish the relationship between a computer node and a subnet node.
        Args:
            relationships (list): database query-based relationships.
            graph (list): list with the nodes that will later form the graph using cytoscape.
        """
        for edge in relationships:
            computer_id, computer_node = self.__define_computer_node(
                edge["p"].start_node
            )
            graph.append(computer_node)
            new_edge = self.__define_edge_computer_subnet(edge, computer_id)
            graph.append(new_edge)

    def define_all_graph(self) -> list:
        """Method that returns the entire graph to later be represented in cytoscape.
        Returns:
            list:Resulting graph.
        """
        graph_result = []
        subnets = self.__graph_driver.get_subnets()
        self.__parse_subnets_all_graph(subnets, graph_result)
        computers_part_of = self.__graph_driver.graph_with_computers()
        self.__computer_part_of_relationship(computers_part_of, graph_result)
        admin_users = self.__graph_driver.graph_psexec_users()
        self.__computer_psexec_relationships(admin_users, graph_result)
        computers_not_psexec = self.__graph_driver.graph_not_psexec_users()
        self.__computer_not_psexec_relationships(computers_not_psexec, graph_result)
        return graph_result

    def __only_psexec_users(self, relationship: list) -> list:
        """Method that returns a graph with the relation computer and administrator.

        Args:

            relationships (list): database query-based relationships.

        Returns:
            list: Resulting graph.
        """
        graph = []
        computers_used = []
        for edge in relationship:
            user_id, user_node = self.__define_admin_user_node(edge["p"].start_node)
            graph.append(user_node)
            computer_id, computer_node = self.__define_computer_node(edge["p"].end_node)
            if computer_id not in computers_used:
                graph.append(computer_node)
                computers_used.append(computer_id)
            new_edge = self.__define_edge_admin_user_computer(computer_id, user_id)
            graph.append(new_edge)
        return graph

    def __define_edge_admin_user_computer(self, computer_id: str, user_id: str) -> dict:
        """Method to define the link between an administrator and a computer.

        Args:
            computer_id (str): Identifier of the computer.
            user_id (str): [ Identifier of the user ]

        Returns:
            dict: Returns the new edge between a user and a computer.
        """
        return {
            "classes": "admin_arrow",
            "data": {
                "source": user_id,
                "target": computer_id,
            },
        }

    def __define_admin_user_node(self, node: Node) -> Tuple[str, Node]:
        """Method to set the format of the admin node.

        Args:
            node (Node): Neo4j node from py2neo.

        Returns:
            Tuple[str, Node]: The id of the node and the node itself.
        """
        user_id = node["ip"] + node["username"]
        if ("password" and "ntlm") in node.labels:
            user_node = {
                "classes": "admin",
                "data": {
                    "id": user_id,
                    "label": node["username"],
                    "username": node["username"],
                    "password": node["password"],
                    "ntlm": node["ntlm"],
                },
            }
        elif "ntlm" in node.keys():
            user_node = {
                "classes": "admin",
                "data": {
                    "id": user_id,
                    "label": node["username"],
                    "username": node["username"],
                    "ntlm": node["ntlm"],
                },
            }
        else:
            user_node = {
                "classes": "admin",
                "data": {
                    "id": user_id,
                    "label": node["username"],
                    "username": node["username"],
                    "password": node["password"],
                },
            }

        return user_id, user_node

    def __only_not_psexec_users(self, relationship: list) -> list:
        """ Method that returns a graph with the relation computer and normal user.

        Args:
            relationships (list): database query-based relationships.

        Returns:
            list: Resulting graph.

        """
        graph = []
        computers_used = []
        for edge in relationship:
            user_id, user_node = self.__define_normal_user_node(edge["p"].start_node)
            graph.append(user_node)
            computer_id, computer_node = self.__define_computer_node(edge["p"].end_node)
            if computer_id not in computers_used:
                graph.append(computer_node)
                computers_used.append(computer_id)

            new_edge = self.__define_edge_normal_user_computer(computer_id, user_id)
            graph.append(new_edge)
        return graph

    def __define_edge_normal_user_computer(
        self, computer_id: str, user_id: str
    ) -> dict:
        """Method to define an edge  between a user and a computer.

        Args:
            computer_id (str): The computer identifier.
            user_id (str): The user identifier.

        Returns:
            Tuple[str, Node]: The id of the node and the node itself.
        """
        return {
            "classes": "user_arrow",
            "data": {
                "source": user_id,
                "target": computer_id,
            },
        }

    def __define_normal_user_node(self, node: Node) -> Tuple[str, dict]:
        """Method to define a non-administrator user.

        Args:

            node (Node): Neo4j node from py2neo.

        Returns:
            Tuple[str,dict]: the user id of the node and the node itself.
        """

        user_id = node["ip"] + node["username"]
        if ("password" and "ntlm") in node.labels:
            user_node = {
                "classes": "user",
                "data": {
                    "id": user_id,
                    "label": node["username"],
                    "username": node["username"],
                    "password": node["password"],
                    "ntlm": node["ntlm"],
                },
            }
        elif "ntlm" in node.keys():
            user_node = {
                "classes": "user",
                "data": {
                    "id": user_id,
                    "label": node["username"],
                    "username": node["username"],
                    "ntlm": node["ntlm"],
                },
            }
        else:
            user_node = {
                "classes": "user",
                "data": {
                    "id": user_id,
                    "label": node["username"],
                    "username": node["username"],
                    "password": node["password"],
                },
            }

        return user_id, user_node

    def __define_computer_node(self, node: Node) -> Tuple[str, dict]:
        """Method to define the node information of a computer.

        Args:
            node (Node): Neo4j node from py2neo.
        Returns:
            Tuple[str,dict]: the computer id of the node and the node itself.
        """
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

    def __define_edge_computer_subnet(self, edge: dict, computer_id: str) -> dict:
        """Method to define the link between a subnet and a computer.
        Args:
            edge (dict): Edge between a computer and a subnet defined by py2neo.
            computer_id (str): The computer identifier.

        Returns:

            dict: The edge between the computer and the subnet.
        """
        subnet_id = edge["p"].end_node["subnet"]
        return {
            "classes": "computer_arrow",
            "data": {"source": computer_id, "target": subnet_id},
        }

    def __parse_subnet_with_computers(self, subnets: list, graph: list) -> None:
        """Method to create subnet nodes for cytoscape.

        Args:
            subnets (list):neo4j subnet nodes.
            graph (list): Resulting graph with subnets and computers.
        """
        for subnet in subnets:
            node = {
                "classes": "subnet",
                "data": {
                    "id": subnet["s"]["subnet"],
                    "label": subnet["s"]["subnet"],
                    "subnet": subnet["s"]["subnet"],
                },
            }
            graph.append(node)

    def __only_part_of_computer(self, relationship: list) -> list:
        """Method to create a graph with only subnets and computers.

        Args:
            relationship (list): neo4j relationships with hosts and subnets.

        Returns:
            list: Graph with only subnets and computers.
        """
        graph = []
        subnets = self.__graph_driver.get_subnets_with_computers_detected()
        self.__parse_subnet_with_computers(subnets, graph)
        for edge in relationship:
            computer_id, computer_node = self.__define_computer_node(
                edge["p"].start_node
            )
            graph.append(computer_node)
            new_edge = self.__define_edge_computer_subnet(edge, computer_id)
            graph.append(new_edge)
        return graph

    def graph_psexec_users(self) -> list:
        """Method to create a graph with admin users and computers in cytoscape.

        Returns:
            list: Resulting graph
        """
        relationship = self.__graph_driver.graph_psexec_users()
        return self.__only_psexec_users(relationship)

    def graph_not_psexec_users(self) -> list:
        """Method to create a graph with normal users and computers in cytoscape.

        Returns:
            list: Resulting Graph.
        """
        relationship = self.__graph_driver.graph_not_psexec_users()
        return self.__only_not_psexec_users(relationship)

    def graph_with_computers(self) -> list:
        """Method to create a graph with subnets and computers in cytoscape.

        Returns:
            list: Resulting Graph.
        """
        relationship = self.__graph_driver.graph_with_computers()
        return self.__only_part_of_computer(relationship)
