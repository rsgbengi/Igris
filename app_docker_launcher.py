from unicodedata import name
import docker


def start():
    client = docker.from_env()
    client.containers.run(
        "neo4j",
        name="neo4j",
        ports={"7474": "7474", "7687": "7687"},
        environment={"NEO4J_AUTH": "neo4j/igris"},
    )
    client.images.build(path=".", tag="igris")
    client.containers.run("igris", name="igris-app")


start()
