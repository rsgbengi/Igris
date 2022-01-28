#!/usr/bin/env python3
from loguru import logger
from neo4j import GraphDatabase
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
            self.__driver = GraphDatabase.driver(
                self.__url, auth=(self.__user, self.__passwd)
            )
        except Exception:
            self.__error_logger.error("Failed to create de driver")

    def close(self):
        if self.__driver is not None:
            self.__driver.close()

    def check_if_subnet_exits(self, subnet: str) -> bool:
        exits_node = False
        response = self.query(
            "OPTIONAL MATCH (s:Subnet{subnet:'"
            + subnet
            + "'}) RETURN s IS NOT NULL AS Status",
            db="neo4j",
        )
        if response is not None:
            exits_node = response[0]["Status"]
        return exits_node

    def check_if_a_user_is_created(self, user: str, passwd: str) -> bool:
        exits_node = False
        response = self.query(
            "OPTIONAL MATCH (u:User{user:'"
            + user
            + "', password:'"
            + passwd
            + "'}) RETURN u IS NOT NULL AS Status",
            db="neo4j",
        )
        if response is not None:
            exits_node = response[0]["Status"]
        return exits_node

    def check_if_match_user_subnet_exits(
        self, user: str, passwd: str, subnet: str
    ) -> list:
        response = self.query(
            "MATCH (u:User {user: '"
            + user
            + "',password:'"
            + passwd
            + "'})-[r:USED_IN]->(s:Subnet{subnet: '"
            + subnet
            + "'}) RETURN type(r)"
        )
        return response

    def init_new_subnet(self, subnet: str) -> None:
        self.query("CREATE (:Subnet {subnet:'" + subnet + "'})", db="neo4j")

    def init_user_used_in_a_subnet(self, user: str, passwd: str, subnet: str) -> bool:
        exits_match = False
        if not self.check_if_a_user_is_created(user, passwd):
            self.query(
                "CREATE (:User {user: '" + user + "',password: '" + passwd + "'})"
            )
        if self.check_if_match_user_subnet_exits(user, passwd, subnet) == []:
            self.query(
                "MATCH (s:Subnet),(u:User) WHERE s.subnet = '"
                + subnet
                + "' and u.user='"
                + user
                + "' and u.password = '"
                + passwd
                + "'CREATE (u) - [r:USED_IN] -> (s)"
            )
        else:
            exits_match = True
        return exits_match

    def number_of_computers_collected(self, subnet: str) -> list:
        response = self.query(
            "MATCH (s:Subnet{subnet:'"
            + subnet
            + "'})<- [r:COMPUTER_OF]-() RETURN COUNT(r)"
        )
        print(response[0])
        return response[0]

    def user_of_computer_used(
        self, user_status: UserInfo, target_info: TargetInfo
    ) -> None:
        self.query(
            "CREATE (:User {user: '"
            + user_status.user
            + "',password: '"
            + user_status.passwd
            + "'})"
        )
        if target_info.psexec:
            """MATCH (c:Computer) WITH c MATCH (s:Subnet) WHERE c.ipv4="192.168.253.137" and s.subnet="192.168.253.0/24" CREATE (c) - [:PART_OF] ->(s)"""
            self.query(
                "MATCH (c:Computer),(u:User) WHERE c.ip = '"
                + target_info.ip
                + "' and u.user='"
                + user_status.user
                + "' and u.password = '"
                + user_status.passwd
                + "' and CREATE (u) - [r:PSEXEC_HERE] -> (c)",
                db="neo4j",
            )
        else:
            self.query(
                "MATCH (c:Computer),(u:User) WHERE c.ip = '"
                + target_info.ip
                + "' and u.user='"
                + user_status.user
                + "' and u.password = '"
                + user_status.passwd
                + "' and CREATE (u) - [r:NOT_PSEXEC_HERE] -> (c)",
                db="neo4j",
            )

    def __check_computer_node(self, target_info: TargetInfo) -> bool:
        exits_node = False
        response = self.query(
            "OPTIONAL MATCH (c:Computer{ip:'"
            + target_info.ip
            + "', os:'"
            + target_info.os
            + "', computer_name: '"
            + target_info.computer_name
            + "',signed:'"
            + str(target_info.signed)
            + "'}) RETURN c IS NOT NULL AS Status",
            db="neo4j",
        )
        if response is not None:
            exits_node = response[0]["Status"]
        return exits_node

    def create_computer_node(
        self, target_info: TargetInfo, user_status: UserInfo
    ) -> None:
        if not self.__check_computer_node(target_info):
            self.query(
                "CREATE (:Computer {ipv4: '"
                + target_info.ip
                + "', os:'"
                + target_info.os
                + "',computer_name:'"
                + target_info.computer_name
                + "',signed:'"
                + str(target_info.signed)
                + "'})",
                db="neo4j",
            )
            self.query(
                "MATCH (s:Subnet),(c:Computer) WHERE s.subnet = '"
                + target_info.subnet
                + "' and c.ip='"
                + target_info.ip
                + "'CREATE (c) - [r:COMPUTER_OF] -> (s)"
            )
            self.user_of_computer_used(user_status, target_info)

    def query(self, query: str, parameters=None, db=None):
        session = None
        response = None
        print(query)
        try:
            if db is not None:
                session = self.__driver.session(database=db)
            else:
                session = self.__driver.session()
            response = list(session.run(query, parameters))

        except Exception as e:
            print(e)
            self.__error_logger.error("Query failed")
        finally:
            if session is not None:
                session.close()
        print(response)
        return response
