from ..utils import Neo4jConnection


class GraphGenerator:
    def __init__(self) -> None:
        self.__graph_driver = Neo4jConnection(
            "neo4j://localhost:7687",
            "neo4j",
            "islaplana56",
        )

    def __parse_subnets(self, subnets, graph):
        for subnet in subnets:
            node = {
                "classes": "subnet",
                "data": {
                    "id": subnet["subnet"],
                    "label": subnet["subnet"],
                    "subnet": subnet["subnet"],
                },
            }
            graph.append(node)

    def __computer_psexec_relationships(self, relationships, graph):
        for edge in relationships:
            user_id, user_node = self.__define_admin_user_node(edge["p"].start_node)
            graph.append(user_node)
            computer_id = edge["p"].end_node["computer_name"]
            new_edge = self.__define_edge_admin_user_computer(computer_id, user_id)
            graph.append(new_edge)

    def __computer_not_psexec_relationships(self, relationships, graph):
        for edge in relationships:
            user_id, user_node = self.__define_normal_user_node(edge["p"].start_node)
            graph.append(user_node)
            computer_id = edge["p"].end_node["computer_name"]
            new_edge = self.__define_edge_normal_user_computer(computer_id, user_id)
            graph.append(new_edge)

    def __computer_part_of_relationship(self, relationships, graph):
        for edge in relationships:
            computer_id, computer_node = self.__define_computer_node(
                edge["p"].start_node
            )
            graph.append(computer_node)
            new_edge = self.__define_edge_computer_subnet(edge, computer_id)
            graph.append(new_edge)

    def __define_nodes(self, graph_result):
        subnets = self.__graph_driver.get_subnets()
        self.__parse_subnets(subnets, graph_result)
        return graph_result

    def __define_edges(self, graph_result):
        computers_part_of = self.__graph_driver.graph_with_computers()
        self.__computer_part_of_relationship(computers_part_of, graph_result)
        admin_users = self.__graph_driver.graph_psexec_users()
        self.__computer_psexec_relationships(admin_users, graph_result)
        computers_not_psexec = self.__graph_driver.graph_not_psexec_users()
        self.__computer_not_psexec_relationships(computers_not_psexec, graph_result)
        return graph_result

    def all_graph(self):
        graph_result = []
        self.__define_nodes(graph_result)
        self.__define_edges(graph_result)
        return graph_result

    def __only_psexec_users(self, relationship):
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

    def __define_edge_admin_user_computer(self, computer_id, user_id):
        return {
            "classes": "admin_arrow",
            "data": {
                "source": user_id,
                "target": computer_id,
            },
        }

    def __define_admin_user_node(self, node):
        user_id = node["ip"] + node["username"] + node["password"]
        user_node = {
            "classes": "admin",
            "data": {
                "id": user_id,
                "label": node["username"] + "/" + node["password"],
                "username": node["username"],
                "password": node["password"],
            },
        }
        return user_id, user_node

    def __only_not_psexec_users(self, relationship):
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

    def __define_edge_normal_user_computer(self, computer_id, user_id):
        return {
            "classes": "user_arrow",
            "data": {
                "source": user_id,
                "target": computer_id,
            },
        }

    def __define_normal_user_node(self, node):
        user_id = node["ip"] + node["username"] + node["password"]
        user_node = {
            "classes": "user",
            "data": {
                "id": user_id,
                "label": node["username"] + "/" + node["password"],
                "username": node["username"],
                "password": node["password"],
            },
        }
        return user_id, user_node

    def __define_computer_node(self, node):
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

    def __define_edge_computer_subnet(self, edge, computer_id):
        subnet_id = edge["p"].end_node["subnet"]
        return {
            "classes": "computer_arrow",
            "data": {"source": computer_id, "target": subnet_id},
        }

    def __only_part_of_computer(self, relationship):
        graph = []
        subnets = self.__graph_driver.get_subnets()
        self.__parse_subnets(subnets, graph)
        for edge in relationship:
            computer_id, computer_node = self.__define_computer_node(
                edge["p"].start_node
            )
            graph.append(computer_node)
            new_edge = self.__define_edge_computer_subnet(edge, computer_id)
            graph.append(new_edge)
        return graph

    def graph_psexec_users(self):
        relationship = self.__graph_driver.graph_psexec_users()
        return self.__only_psexec_users(relationship)

    def graph_not_psexec_users(self):
        relationship = self.__graph_driver.graph_not_psexec_users()
        return self.__only_not_psexec_users(relationship)

    def graph_with_computers(self):
        relationship = self.__graph_driver.graph_with_computers()
        return self.__only_part_of_computer(relationship)

