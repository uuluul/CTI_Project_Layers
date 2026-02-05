import os
from dotenv import load_dotenv
from opensearchpy import OpenSearch

load_dotenv()

def get_opensearch_client():
    return OpenSearch(
        hosts=[{'host': 'localhost', 'port': 9200}],
        http_compress=True,
        use_ssl=False,
    )

def create_index():
    client = get_opensearch_client()
    index_name = "security-logs-knn"

    index_body = {
        "settings": {
            "index": {
                "knn": True,
                "knn.algo_param.ef_search": 100
            }
        },
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "log_text": {"type": "text"},
                # 定義向量
                "log_vector": {
                    "type": "knn_vector",
                    "dimension": 1536,  # OpenAI text-embedding-3-small 的維度
                    "method": {
                        "name": "hnsw",
                        "space_type": "l2",
                        "engine": "faiss"
                    }
                }
            }
        }
    }

    if not client.indices.exists(index=index_name):
        response = client.indices.create(index=index_name, body=index_body)
        print(f"  Index '{index_name}' 建立成功！")
        print(response)
    else:
        print(f"  Index '{index_name}' 已經存在，跳過建立步驟。")

if __name__ == "__main__":
    create_index()