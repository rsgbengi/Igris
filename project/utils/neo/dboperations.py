#!/usr/bin/env python3
from loguru import logger
import loguru
from py2neo import Node, Relationship, Graph
from ..gatherinfo import TargetInfo, UserInfo
from loguru import logger
from log_symbols import LogSymbols


class Neo4jConnection:
    def __init__(
        self,
        url: str,
        user: str,
        passwd: str,
    ) -> None:
        self.__url = url
        self.__user = user
        self.__passwd = passwd
        self.__info_logger = logger.bind(name="igris_info")
        self.__error_logger = logger.bind(name="igris_error")
        try:
            self.__graph = Graph(self.__url, auth=(self.__user, self.__passwd))
        except Exception:
            self.__error_logger.error("Failed to create de driver")

    def relationship_computer_subnet(self, target_info: TargetInfo) -> None:
        computer = self.get_computer(target_info)
        subnet = self.get_subnet(target_info.subnet)
        relationship = Relationship(computer, "PART_OF", subnet)
        self.__commit(relationship)

    def relationship_computer_user(
        self, target_info: TargetInfo, user_status: UserInfo
    ) -> None:
        computer = self.get_computer(target_info)
        user = self.get_user(user_status, target_info.ip)
        if target_info.psexec:
            relationship = Relationship(user, "PSEXEC_HERE", computer)
        else:
            relationship = Relationship(user, "NOT_PSEXEC_HERE", computer)
        self.__commit(relationship)

    def get_computer(self, target_info: TargetInfo) -> Node:
        return self.__graph.nodes.match("Computer", ipv4=target_info.ip).first()

    def init_new_computer(self, target_info: TargetInfo):
        if self.get_computer(target_info) is None:
            computer = Node(
                "Computer",
                os=target_info.os,
                computer_name=target_info.computer_name,
                signed=target_info.signed,
                ipv4=target_info.ip,
            )
            self.__commit(computer)

    def get_user(self, user_status: UserInfo, ipv4: str) -> Node:
        return self.__graph.nodes.match(
            "User", ip=ipv4, username=user_status.user, password=user_status.passwd
        ).first()

    def init_new_user(self, user_status: UserInfo, ipv4: str):
        if self.get_user(user_status, ipv4) is None:
            user = Node(
                "User", ip=ipv4, username=user_status.user, password=user_status.passwd
            )
            self.__commit(user)

    def check_computers_of_a_subnet(self, subnet: str) -> list:
        subnet_node = self.get_subnet(subnet)
        return self.__graph.match(r_type="PART_OF", nodes=(None, subnet_node)).all()

    def check_nodes_with_psexec(self, computer: Node, user_status: UserInfo) -> str:
        nodes_user = self.get_user(user_status, computer["ipv4"])
        if nodes_user is not None:
            relation = self.__graph.match(
                r_type="PSEXEC_HERE", nodes=(nodes_user, computer)
            ).all()
        else:
            return ""

        return "Psexec Here!" if relation else "Not Psexec Here"

    def check_if_subnet_exits(self, subnet: str) -> bool:
        subnet = self.get_subnet(subnet)
        return subnet is not None

    def __commit(self, object_to_commit) -> None:
        tx = self.__graph.begin()
        tx.create(object_to_commit)
        tx.commit()

    def get_subnet(self, subnet) -> Node:
        subnet = self.__graph.nodes.match("Subnet", subnet=subnet).first()
        return subnet

    def __relatoinship_subnet_subnet(self, new_node, last_node):
        relationship = Relationship(last_node, "ANALIZE", new_node)
        self.__commit(relationship)

    def init_new_subnet(self, subnet: str) -> None:
        subnets = self.get_subnets()
        subnet_node = Node("Subnet", subnet=subnet)
        self.__commit(subnet_node)
        if len(subnets) != 0:
            self.__relatoinship_subnet_subnet(subnet_node, subnets[len(subnets) - 1])

    def graph_psexec_users(self):
        return self.__graph.run("MATCH p=()-[r:PSEXEC_HERE]->() RETURN p").data()

    def graph_not_psexec_users(self):
        return self.__graph.run("MATCH p=()-[r:NOT_PSEXEC_HERE]->() RETURN p").data()

    def graph_with_computers(self):
        return self.__graph.run("MATCH p=()-[r:PART_OF]->() RETURN p").data()

    def get_subnets(self):
        return self.__graph.nodes.match("Subnet").all()

    def get_subnets_with_computers_detected(self):
        return self.__graph.run(
            "MATCH (n:Subnet) WHERE size( (n)--() ) > 1 RETURN n"
        ).data()
