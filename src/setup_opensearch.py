import os
from dotenv import load_dotenv
from opensearchpy import OpenSearch

# 載入設定
load_dotenv()

def get_opensearch_client():
    # 因為我們在 Docker 裡關閉了安全性插件，所以用 http 且不用帳密
    return OpenSearch(
        hosts=[{'host': 'localhost', 'port': 9200}],
        http_compress=True,
        use_ssl=False,
    )

def create_index():
    client = get_opensearch_client()
    index_name = "security-logs-knn"

    # 定義 Index 設定 (啟用 k-NN)
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
                # 關鍵：定義向量欄位
                "log_vector": {
                    "type": "knn_vector",
                    "dimension": 1536,  # OpenAI text-embedding-3-small 的維度
                    "method": {
                        "name": "hnsw",
                        "space_type": "l2", # 使用歐幾里得距離 (L2)
                        "engine": "faiss"
                    }
                }
            }
        }
    }

    if not client.indices.exists(index=index_name):
        response = client.indices.create(index=index_name, body=index_body)
        print(f"✅ Index '{index_name}' 建立成功！")
        print(response)
    else:
        print(f"⚠️ Index '{index_name}' 已經存在，跳過建立步驟。")

if __name__ == "__main__":
    create_index()