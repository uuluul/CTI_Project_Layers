import json
import re
import os

# 設定檔案路徑
STIX_FILE = "out/bundle_stix21.json" 
def load_stix_indicators(filepath):
    """
    從 STIX 檔案中提取出 blacklist
    """
    if not os.path.exists(filepath):
        print(f"  找不到 STIX 檔案: {filepath}")
        return []

    with open(filepath, 'r', encoding='utf-8') as f:
        bundle = json.load(f)

    iocs = []
    
    # 抓取 indicator
    for obj in bundle.get("objects", []):
        if obj.get("type") == "indicator":
            pattern = obj.get("pattern", "")
            match = re.search(r"value\s*=\s*'([^']+)'", pattern)
            if match:
                ioc_value = match.group(1)
                iocs.append({
                    "value": ioc_value,
                    "name": obj.get("name"),
                    "id": obj.get("id")
                })
    
    print(f"  從 STIX 載入了 {len(iocs)} 個黑名單指標 (IOCs)")
    return iocs

def check_logs_against_rules(log_text, iocs):
    """
    規則比對：檢查 Log 裡面有沒有包含黑名單字串
    """
    detected = False
    print(f"\n  [Layer 4 規則掃描] 分析 Log: {log_text}")
    
    for ioc in iocs:
        # 字串比對 如果黑名單 IP 出現在 Log 裡
        if ioc["value"] in log_text:
            print(f"     [命中規則] 發現已知威脅！")
            print(f"      - 偵測對象: {ioc['value']}")
            print(f"      - STIX 指標: {ioc['name']}")
            detected = True
            
    if not detected:
        print("     未觸發靜態規則 (不在黑名單內)")

def main():
    iocs = load_stix_indicators(STIX_FILE)
    
    if not iocs:
        print("  沒有黑名單可以比對，請先執行 run_pipeline.py 產生 STIX 檔。")
        return

    # test case
    
    # case A: 剛好命中 CTI 報告裡的惡意 IP 
    test_log_1 = "Connection attempt from malicious IP 203.0.113.10 on port 443." 
    
    # case B: 正常的 Log
    test_log_2 = "User admin logged in from 192.168.1.1."
    
    check_logs_against_rules(test_log_1, iocs)
    check_logs_against_rules(test_log_2, iocs)

if __name__ == "__main__":
    main()