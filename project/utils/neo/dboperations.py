#!/usr/bin/env python3
from loguru import logger
from py2neo import Node, Relationship, Graph
from ..gatherinfo import TargetInfo, UserInfo


class Neo4jConnection:
    def __init__(
        self,
        url: str,
        user: str,
        passwd: str,
        info_logger: logger,
        error_logger: logger,
    ) -> None:
        self.__url = url
        self.__user = user
        self.__passwd = passwd
        self.__dirver = None
        self.__info_logger = info_logger
        self.__error_logger = error_logger
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
        computer = self.__graph.nodes.match("Computer", ipv4=target_info.ip).first()
        return computer

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
        user = self.__graph.nodes.match(
            "User", ip=ipv4, username=user_status.user, password=user_status.passwd
        ).first()
        return user

    def init_new_user(self, user_status: UserInfo, ipv4: str):
        if self.get_user(user_status, ipv4) is None:
            user = Node(
                "User", ip=ipv4, username=user_status.user, password=user_status.passwd
            )
            self.__commit(user)

    def check_computers_of_a_subnet(self, subnet: str) -> list:
        subnet_node = self.get_subnet(subnet)
        nodes = self.__graph.match(r_type="PART_OF", nodes=(None, subnet_node)).all()
        return nodes

    def check_nodes_with_psexec(self, computer: Node, user_status: UserInfo) -> str:
        nodes_user = self.get_user(user_status, computer["ipv4"])
        print("hola")
        print(nodes_user)
        if nodes_user is not None:
            relation = self.__graph.match(
                r_type="PSEXEC_HERE", nodes=(nodes_user, computer)
            ).all()
            print(relation)
        else:
            return None

        if not relation:
            return "Psexec Here!"
        else:
            return "Not Psexec Here"

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

    def init_new_subnet(self, subnet: str) -> None:
        subnet_node = Node("Subnet", subnet=subnet)
        self.__commit(subnet_node)
