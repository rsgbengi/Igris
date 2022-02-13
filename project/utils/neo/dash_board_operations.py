from py2neo import Graph


class DashBoardOperations:
    def __init__(self, driver: Graph):
        self.__driver = driver

    def graph_psexec_users(self):
        relationship = self.__driver.run(
            "MATCH p=()-[r:PSEXEC_HERE]->() RETURN p"
        ).data()
        new_graph = self.__only_psexec_users(relationship)
        return new_graph

    def graph_not_psexec_users(self):
        relationship = self.__driver.run(
            "MATCH p=()-[r:NOT_PSEXEC_HERE]->() RETURN p"
        ).data()
        new_graph = self.__only_not_psexec_users(relationship)
        return new_graph

    def graph_with_computers(self):
        relationship = self.__driver.run("MATCH p=()-[r:PART_OF]->() RETURN p").data()
        return self.__only_part_of_computer(relationship, self.__driver)

    def __only_psexec_users(self, relationship):
        graph = []
        computers_used = []
        for edge in relationship:

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

    def __only_not_psexec_users(self, relationship):
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

    def __only_part_of_computer(self, relationship, graph_driver):
        graph = []
        subnets = graph_driver.nodes.match("Subnet").all()
        parse_subnets(subnets, graph)
        for edge in relationship:
            computer_node = {
                "classes": "computer",
                "data": {
                    "id": edge["p"].start_node["computer_name"],
                    "label": edge["p"].start_node["computer_name"],
                    "computer_name": edge["p"].start_node["computer_name"],
                    "ipv4": edge["p"].start_node["ipv4"],
                    "os": edge["p"].start_node["os"],
                    "signed": edge["p"].start_node["signed"],
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
