#!/usr/bin/env python3
from loguru import logger
from py2neo import Node, Relationship, Graph, ServiceUnavailable

from spnego._ntlm_raw.crypto import is_ntlm_hash
from ..recon import TargetInfo, UserInfo

from loguru import logger


class Neo4jConnection:
    """[ Class to generate connections to the database ]

    Args:
        url (str): [ url to connect to database]
        user (str): [User of the database (neo4j)]
        passwd (str): [Password of the database(igris)]
    """

    def __init__(
        self,
        url: str,
        user: str,
        passwd: str,
    ) -> None:
        self.__url = url
        self.__user = user
        self.__passwd = passwd
        self.__info_logger = logger.bind(name="info")
        self.__error_logger = logger.bind(name="error")
        try:
            self.__info_logger.debug("The neo4j dirver has been created successfully")
            self.__graph = Graph(self.__url, auth=(self.__user, self.__passwd))
        except Exception:
            self.__error_logger.error("Failed to create de driver")

    def relationship_computer_subnet(self, target_info: TargetInfo) -> None:
        """[Method that executes a query to obtain the relationships between host and subnet]

        Args:
            target_info (TargetInfo): [Computer information]
        """
        computer = self.get_computer(target_info)
        subnet = self.get_subnet(target_info.subnet)
        relationship = Relationship(computer, "PART_OF", subnet)
        self.__commit(relationship)

    def relationship_computer_user(
        self, target_info: TargetInfo, user_status: UserInfo
    ) -> None:
        """[Method that executes a query to obtain the relationships between computer and normal user]

        Args:
            target_info (TargetInfo): [Computer information]
            user_status (UserInfo): [User information]
        """
        computer = self.get_computer(target_info)
        user = self.get_user(user_status, target_info.ip)
        if target_info.psexec:
            relationship = Relationship(user, "PSEXEC_HERE", computer)
        else:
            relationship = Relationship(user, "NOT_PSEXEC_HERE", computer)
        self.__commit(relationship)

    def get_computer(self, target_info: TargetInfo) -> Node:
        """[Method to get a specific computer of the database]

        Args:
            target_info (TargetInfo): [ Computer information to obtain the ipv4 of the computer ]

        Returns:
            Node: _description_
        """
        return self.__graph.nodes.match("Computer", ipv4=target_info.ip).first()

    def init_new_computer(self, target_info: TargetInfo):
        """[Method to insert a new computer to the database]

        Args:
            target_info (TargetInfo): [ Computer Information ]
        """
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
        """[ Method to get a specific user ]

        Args:
            user_status (UserInfo): [ User information to get a specific user from the datbase ]
            ipv4 (str): [ Ipv4 of a specific computer ]

        Returns:
            Node: [The user node ]
        """
        return self.__graph.nodes.match(
            "User", ip=ipv4, username=user_status.user.lower()
        ).first()

    def __create_user_node(self, user_status: UserInfo, ipv4: str) -> None:
        """[ Create a user node from scratch ]

        Args:
            user_status (UserInfo): [ User information ]
            ipv4 (str): [ ipv4 of teh computer target ]
        """
        if not is_ntlm_hash(user_status.passwd):
            user = Node(
                "User",
                ip=ipv4,
                username=user_status.user.lower(),
                password=user_status.passwd,
            )
        else:
            user = Node(
                "User",
                ip=ipv4,
                username=user_status.user.lower(),
                ntlm=user_status.passwd,
            )
        self.__commit(user)

    def init_new_user(self, user_status: UserInfo, ipv4: str):
        """[ Method to start a new user ]

        Args:
            user_status (UserInfo): [User information to create a new user node  ]
            ipv4 (str): [Ip of a specific computer ]
        """
        check_node = self.get_user(user_status, ipv4)
        if check_node is None:
            self.__create_user_node(user_status, ipv4)
        else:
            if not is_ntlm_hash(user_status.passwd):
                check_node["password"] = user_status.passwd
            else:
                check_node["ntlm"] = user_status.passwd
            self.__graph.push(check_node)

    def check_computers_of_a_subnet(self, subnet: str) -> list:
        """[ Returns all computers of a specific subnet ]

        Args:
            subnet (str): [ Subnet from where to take the computers ]

        Returns:
            list: [ list with subnet and computers nodes ]
        """
        subnet_node = self.get_subnet(subnet)
        return self.__graph.match(r_type="PART_OF", nodes=(None, subnet_node)).all()

    def check_nodes_with_psexec(self, computer: Node, user_status: UserInfo) -> str:
        """[ Method to validate if a user is an administrator on a computer ]

        Args:
            computer (Node): [ The computer node]
            user_status (UserInfo): [The information of the user ]

        Returns:
            str: [ The resolution of the query ]
        """
        nodes_user = self.get_user(user_status, computer["ipv4"])
        if nodes_user is not None:
            relation = self.__graph.match(
                r_type="PSEXEC_HERE", nodes=(nodes_user, computer)
            ).all()
        else:
            return ""

        return "Psexec Here!" if relation else "Not Psexec Here"

    def check_if_subnet_exits(self, subnet: str) -> bool:
        """[ Method to check if a function exists ]

        Args:
            subnet (str): _description_

        Returns:
            bool: _description_
        """
        subnet = self.get_subnet(subnet)
        return subnet is not None

    def __commit(self, object_to_commit) -> None:
        """[Method to commit changes to the database]

        Args:
            object_to_commit (_type_): [Relationship or node to enter in the database]
        """
        tx = self.__graph.begin()
        tx.create(object_to_commit)
        tx.commit()

    def get_subnet(self, subnet: str) -> Node:
        """[ Method to get a specific subnet node ]

        Args:
            subnet (str): [ Function to grab a specific subnet node ]

        Returns:
            Node: [ The subnet node ]
        """
        return self.__graph.nodes.match("Subnet", subnet=subnet).first()

    def __relatoinship_subnet_subnet(self, new_node: Node, last_node: Node) -> None:
        """[ Establish relationship between two subnets ]

        Args:
            new_node (Node): [ New subnet node introduced ]
            last_node (Node): [ The last inserted subnet node ]
        """
        relationship = Relationship(last_node, "ANALIZE", new_node)
        self.__commit(relationship)

    def init_new_subnet(self, subnet: str) -> None:
        """[ Method to init a new subnet node ]

        Args:
            subnet (str): [ Subnet to create the node ]
        """
        subnets = self.get_subnets()
        subnet_node = Node("Subnet", subnet=subnet)
        self.__commit(subnet_node)
        if len(subnets) != 0:
            self.__relatoinship_subnet_subnet(subnet_node, subnets[len(subnets) - 1])

    def graph_psexec_users(self) -> list:
        """[ Method to return no]

        Returns:
            list: _description_
        """
        return self.__graph.run("MATCH p=()-[r:PSEXEC_HERE]->() RETURN p").data()

    def graph_not_psexec_users(self) -> list:
        return self.__graph.run("MATCH p=()-[r:NOT_PSEXEC_HERE]->() RETURN p").data()

    def graph_with_computers(self) -> list:
        return self.__graph.run("MATCH p=()-[r:PART_OF]->() RETURN p").data()

    def get_subnets(self) -> list:
        return self.__graph.nodes.match("Subnet").all()

    def get_subnets_with_computers_detected(self):
        return self.__graph.run(
            "MATCH (s:Subnet)-[r:PART_OF]-(c:Computer) RETURN s"
        ).data()

    def check_status(self) -> bool:
        alive = True
        try:
            self.__graph.run("Match () Return 1 Limit 1")
        except ServiceUnavailable:
            alive = False
        return alive
