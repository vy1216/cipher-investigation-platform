from dotenv import load_dotenv
import os
import certifi
from neo4j import GraphDatabase

load_dotenv()
os.environ.setdefault("SSL_CERT_FILE", certifi.where())
required=("NEO4J_URI","NEO4J_USERNAME","NEO4J_PASSWORD")
missing=[k for k in required if not os.getenv(k)]
if missing:
    raise SystemExit("Missing Neo4j settings in .env: " + ", ".join(missing))

driver=GraphDatabase.driver(os.environ["NEO4J_URI"], auth=(os.environ["NEO4J_USERNAME"], os.environ["NEO4J_PASSWORD"]))
try:
    driver.verify_connectivity()
    db=os.getenv("NEO4J_DATABASE","neo4j")
    with driver.session(database=db) as session:
        value=session.run("RETURN 1 AS ok").single()["ok"]
    print("NEO4J CONNECTION OK")
    print("database:", db)
    print("ssl_cert_file:", os.environ.get("SSL_CERT_FILE"))
    print("probe:", value)
finally:
    driver.close()
