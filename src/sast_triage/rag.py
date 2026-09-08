"""Legacy retrieval helpers: embed the vulnerable-code dataset or a repository into
Chroma and pull back similar snippets. Used by the exploratory notebook, not by the
triage pipeline.
"""

import json
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


def create_dataframe(dataset_path="vulnerable_codes_programming_languages_dataset.json"):
    return pd.read_json(dataset_path)


def create_embeddings(input: str, k: int = 3):
    df = create_dataframe()

    # 1) Prepare texts
    series = df[df["code"].notna()].copy()
    series["code"] = series["code"].astype(str)

    texts = series["code"].tolist()

    metadatas = [
        {
            "vulnerability": row["vulnerability"],
            "language": row["language"],
            "id": row["id"],
        }
        for _, row in series.iterrows()
    ]

    from langchain_huggingface import HuggingFaceEmbeddings  # noqa: lazy
    from langchain_chroma import Chroma  # noqa: lazy

    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

    vectorstore = Chroma.from_texts(
        texts=texts,
        embedding=embeddings,
        metadatas=metadatas,
        collection_name="code_collection",
        persist_directory="./chroma_db",
    )

    results = vectorstore.similarity_search(input, k=k)
    for r in results:
        print(r.metadata)

    return results


def visualize_embeddings(embeddings, texts):
    from sklearn.manifold import TSNE  # noqa: lazy
    # 3) t-SNE → 3D
    perplexity = min(30, max(2, len(texts) - 1))

    tsne = TSNE(
        n_components=3,
        perplexity=perplexity,
        random_state=42,
        init="pca",
        learning_rate="auto",
    )

    X = np.array(embeddings.embed_documents(texts))
    X_3d = tsne.fit_transform(X)

    # 4) Plot (matplotlib 3D)
    fig = plt.figure(figsize=(10, 8))
    ax = fig.add_subplot(111, projection="3d")

    ax.scatter(
        X_3d[:, 0],
        X_3d[:, 1],
        X_3d[:, 2],
        s=20,
        alpha=0.7
    )

    ax.set_title("3D t-SNE of code embeddings")
    ax.set_xlabel("Dim 1")
    ax.set_ylabel("Dim 2")
    ax.set_zlabel("Dim 3")

    plt.show()


def collect_repo_files(repo_path, exclude_dirs=None, file_extensions=None):
    """
    Recursively collect all files from repo, filtering by extension and exclusions.

    Args:
        repo_path: Path to repository root (string or Path object)
        exclude_dirs: Set of directory names to skip
        file_extensions: Set of file extensions to include

    Returns:
        List of Path objects for all matching files
    """
    if exclude_dirs is None:
        exclude_dirs = {"test", "tests", "docs", "examples", ".git", ".venv", "venv"}
    if file_extensions is None:
        file_extensions = {".java", ".js", ".py", ".cpp", ".c", ".cs", ".rb", ".go"}

    repo = Path(repo_path)
    files = []

    # Walk through all items in the directory
    for item in repo.iterdir():
        # Skip excluded directories entirely
        if item.is_dir() and item.name in exclude_dirs:
            continue

        # If it's a file with matching extension, add it
        if item.is_file() and item.suffix in file_extensions:
            files.append(item)

        # If it's a directory, recurse into it
        elif item.is_dir():
            files.extend(collect_repo_files(item, exclude_dirs, file_extensions))

    return files


def read_file_text(file_path, max_size=2*1024*1024):
    """
    Safely read file content with size limit.

    Args:
        file_path: Path object to the file
        max_size: Maximum file size in bytes (default 2MB)

    Returns:
        File content as string, or None if file is too large or unreadable
    """
    try:
        # Check file size first
        if file_path.stat().st_size > max_size:
            print(f"Skipping {file_path.name} (too large)")
            return None

        # Read with UTF-8, ignore encoding errors
        return file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None


def chunk_text(text, chunk_size=2000, overlap=200):
    """
    Split text into overlapping chunks.

    Args:
        text: Full text to chunk
        chunk_size: Target characters per chunk (default 2000)
        overlap: Character overlap between chunks (default 200)

    Returns:
        List of text chunks
    """
    chunks = []
    i = 0
    n = len(text)

    while i < n:
        # Extract chunk
        chunk = text[i : i + chunk_size]
        chunks.append(chunk)

        # Move forward, keeping overlap
        i += chunk_size - overlap

    return chunks


def prepare_repo_for_embeddings(file_list, chunk_size=2000, overlap=200):
    """
    Read repo files, chunk them, and prepare for embeddings.

    Args:
        file_list: List of Path objects from collect_repo_files()
        chunk_size: Characters per chunk (default 2000)
        overlap: Overlap between chunks (default 200)

    Returns:
        Tuple of (texts_list, metadatas_list) where each item is a chunk
    """
    texts = []
    metadatas = []

    for file_path in file_list:
        # Read file content safely
        content = read_file_text(file_path)
        if content is None:
            continue  # Skip if couldn't read

        # Determine language from file extension
        language_map = {
            ".java": "Java",
            ".py": "Python",
            ".js": "JavaScript",
            ".ts": "TypeScript",
            ".cpp": "C++",
            ".c": "C",
            ".cs": "C#",
            ".rb": "Ruby",
            ".go": "Go",
            ".php": "PHP",
        }
        language = language_map.get(file_path.suffix, "Unknown")

        # Chunk the file content
        chunks = chunk_text(content, chunk_size=chunk_size, overlap=overlap)

        # Add each chunk with metadata
        for chunk_idx, chunk in enumerate(chunks):
            texts.append(chunk)
            metadatas.append({
                "file_path": str(file_path),
                "file_name": file_path.name,
                "language": language,
                "chunk_index": chunk_idx,
                "total_chunks": len(chunks),
            })

    print(f"Created {len(texts)} chunks from repository files")
    return texts, metadatas


def build_repo_vectorstore(texts, metadatas, collection_name="repo_context", persist_dir="./chroma_db"):
    """
    Build Chroma vector store from repo chunks.

    Args:
        texts: List of text chunks
        metadatas: List of metadata dicts
        collection_name: Name for the collection
        persist_dir: Directory to persist the vector store

    Returns:
        Chroma vector store object
    """
    from langchain_huggingface import HuggingFaceEmbeddings  # noqa: lazy
    from langchain_chroma import Chroma  # noqa: lazy
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

    vectorstore = Chroma.from_texts(
        texts=texts,
        embedding=embeddings,
        metadatas=metadatas,
        collection_name=collection_name,
        persist_directory=persist_dir,
    )

    print(f"Built vector store with {len(texts)} chunks")
    return vectorstore


def query_repo_context(vectorstore, query, k=5):
    """
    Query the repo vector store for relevant chunks.

    Args:
        vectorstore: Chroma vector store
        query: Search query (string)
        k: Number of results to return

    Returns:
        List of Document objects with metadata
    """
    results = vectorstore.similarity_search(query, k=k)
    return results


def build_analysis_prompt(sast_findings, relevant_docs):
    """
    Build a comprehensive analysis prompt with SAST findings and relevant code context.

    Args:
        sast_findings: Dict/list of SAST scan results
        relevant_docs: List of Document objects retrieved from vector store

    Returns:
        Formatted string with SAST findings and code context
    """
    # Format SAST findings section
    findings_text = "## SAST Scan Findings\n\n"
    if isinstance(sast_findings, dict):
        findings_text += json.dumps(sast_findings, indent=2)
    else:
        findings_text += json.dumps(sast_findings, indent=2)

    # Format relevant code context section
    context_text = "\n\n## Relevant Source Code\n\n"

    if not relevant_docs:
        context_text += "No relevant code context found."
    else:
        for i, doc in enumerate(relevant_docs, 1):
            meta = doc.metadata
            file_name = meta.get('file_name', 'Unknown')
            language = meta.get('language', 'Unknown').lower()
            chunk_idx = meta.get('chunk_index', 0) + 1
            total_chunks = meta.get('total_chunks', 1)
            file_path = meta.get('file_path', 'Unknown')

            context_text += f"### [{i}] {file_name} (chunk {chunk_idx}/{total_chunks})\n"
            context_text += f"**Path:** `{file_path}`\n"
            context_text += f"\\`\\`\\`{language}\n{doc.page_content}\n\\`\\`\\`\n\n"

    return findings_text + context_text

