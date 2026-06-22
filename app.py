from __future__ import annotations

import argparse
import time

from config import (
    ACTOR_DB_DIR,
    ATTACK_DB_DIR,
    DETECTION_DB_DIR,
    ENTERPRISE_ATTACK_JSON,
    MITRE_CTI_DIR,
    MODEL_CACHE_DIR,
    REDTEAM_DB_DIR,
    ROOT_DIR,
    VECTOR_DB_DIR,
    ensure_project_dirs,
    load_settings,
)


AGENTS = ("redteam", "cti", "attribution", "detection")
DATABASES = ("attack", "redteam", "actor", "detection")


def status() -> None:
    ensure_project_dirs()
    settings = load_settings()
    print(f"Project root: {ROOT_DIR}")
    print(f"MITRE CTI repo: {MITRE_CTI_DIR}")
    print(f"MITRE enterprise bundle ready: {ENTERPRISE_ATTACK_JSON.exists()}")
    print(f"Vector DB root: {VECTOR_DB_DIR}")
    print(f"Model cache: {MODEL_CACHE_DIR}")
    print(f"Groq key configured: {bool(settings.groq_api_key)}")
    print(f"Main model: {settings.main_model}")
    print(f"Secondary model: {settings.secondary_model}")
    print(f"Embedding model: {settings.embedding_model}")
    print("Vector DB folders:")
    for path in (ATTACK_DB_DIR, REDTEAM_DB_DIR, ACTOR_DB_DIR, DETECTION_DB_DIR):
        print(f"  - {path}")


def model_from_choice(choice: str) -> str:
    settings = load_settings()
    if choice == "main":
        return settings.main_model
    if choice == "secondary":
        return settings.secondary_model
    return choice


def ask(agent: str, question: str, model_choice: str) -> None:
    model = model_from_choice(model_choice)
    if agent == "redteam":
        from agents.redteam_agent import ask as ask_agent
    elif agent == "cti":
        from agents.cti_agent import ask as ask_agent
    elif agent == "attribution":
        from agents.attribution_agent import ask as ask_agent
    elif agent == "detection":
        from agents.detection_agent import ask as ask_agent
    else:
        raise ValueError(f"Unknown agent: {agent}")
    print(ask_agent(question, model=model))


def raw_search(database: str, question: str, show_all: bool = False) -> None:
    from rag.similarity_search import DATABASES as DB_PATHS
    from rag.similarity_search import format_results, similarity_search

    results = similarity_search(question, DB_PATHS[database], n_results=5)
    print(format_results(results, top_only=not show_all))


def compare(agent: str, question: str) -> None:
    settings = load_settings()
    for label, model in (("main", settings.main_model), ("secondary", settings.secondary_model)):
        started = time.perf_counter()
        print(f"\n=== {label.upper()} MODEL: {model} ===\n")
        ask(agent, question, model)
        elapsed = time.perf_counter() - started
        print(f"\nResponse time: {elapsed:.2f}s")


def main() -> None:
    parser = argparse.ArgumentParser(description="MedFlow AI Cybersecurity Ecosystem")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status", help="Show project setup status.")

    ask_parser = subparsers.add_parser("ask", help="Ask a MedFlow agent.")
    ask_parser.add_argument("--agent", choices=AGENTS, required=True)
    ask_parser.add_argument("--model", default="main", help="Use 'main', 'secondary', or an explicit Groq model ID.")
    ask_parser.add_argument("question")

    search_parser = subparsers.add_parser("search", help="Raw ChromaDB similarity search with no LLM.")
    search_parser.add_argument("--db", choices=DATABASES, required=True)
    search_parser.add_argument("--all", action="store_true", help="Show all top-5 results instead of just the best match.")
    search_parser.add_argument("question")

    compare_parser = subparsers.add_parser("compare", help="Ask one agent with both main and secondary models.")
    compare_parser.add_argument("--agent", choices=AGENTS, required=True)
    compare_parser.add_argument("question")

    args = parser.parse_args()
    if args.command == "status":
        status()
    elif args.command == "ask":
        ask(args.agent, args.question, args.model)
    elif args.command == "search":
        raw_search(args.db, args.question, show_all=args.all)
    elif args.command == "compare":
        compare(args.agent, args.question)


if __name__ == "__main__":
    main()
