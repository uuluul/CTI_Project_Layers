from __future__ import annotations

import json
import os
import time
import shutil
import logging
from datetime import datetime

from dotenv import load_dotenv

from .extract_schema import DEFAULT_SYSTEM_PROMPT, EXTRACTION_SCHEMA_DESCRIPTION
from .llm_client import LLMClient
from .to_stix import build_stix_bundle
from .validate_stix import validate_stix_json
from .utils import ensure_dir, read_text_file, write_json, write_text

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

INPUT_DIR = "data/input"
PROCESSED_DIR = "data/processed"
ERROR_DIR = "data/error"
OUT_DIR = "out"

def build_user_prompt(cti_text: str) -> str:
    return f"""{EXTRACTION_SCHEMA_DESCRIPTION}

CTI_REPORT_TEXT:
{cti_text}
"""

def process_single_file(file_path: str, filename: str, llm: LLMClient) -> None:

    logger.info(f"  開始處理檔案: {filename}")
    
    cti_text = read_text_file(file_path)
    
    # 移除副檔名
    base_name = os.path.splitext(filename)[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    logger.info(f"  正在呼叫 LLM 進行分析...")
    extracted = llm.extract_json(
        system_prompt=DEFAULT_SYSTEM_PROMPT,
        user_prompt=build_user_prompt(cti_text),
    )
    
    # 輸出
    extract_out_path = f"{OUT_DIR}/{base_name}_{timestamp}_extracted.json"
    write_json(extract_out_path, extracted)

    # 轉換 STIX 2.1
    logger.info(f"  正在轉換為 STIX 2.1 格式...")
    stix_json_str = build_stix_bundle(extracted)
    
    # 輸出 STIX Bundle
    stix_out_path = f"{OUT_DIR}/{base_name}_{timestamp}_bundle.json"
    write_text(stix_out_path, stix_json_str)

    # 驗證 STIX 
    ok, val_payload = validate_stix_json(stix_json_str)
    
    # 驗證報告
    val_out_path = f"{OUT_DIR}/{base_name}_{timestamp}_validation.json"
    write_json(val_out_path, val_payload)

    num_indicators = sum(
        len((extracted.get("indicators", {}) or {}).get(k, []))
        for k in ["ipv4", "ipv6", "domains", "urls"]
    )
    
    report = {
        "input_file": filename,
        "processed_at": timestamp,
        "status": "Success",
        "validator_pass": ok,
        "confidence": extracted.get("confidence"),
        "metrics": {
            "indicators": num_indicators,
            "hashes": len((((extracted.get("indicators", {}) or {}).get("hashes", {}) or {}).get("sha256", []))),
            "ttps": len(extracted.get("ttps", []) or []),
        },
        "output_files": {
            "stix_bundle": stix_out_path,
            "validation": val_out_path
        }
    }
    
    # 輸出: 總結報告
    report_out_path = f"{OUT_DIR}/{base_name}_{timestamp}_report.json"
    write_json(report_out_path, report)
    
    logger.info(f"  處理完成! STIX Bundle 已儲存至: {stix_out_path}")
    logger.info(f"  提取統計: IOCs={num_indicators}, TTPs={report['metrics']['ttps']}")

def main() -> None:
    load_dotenv()

    ensure_dir(INPUT_DIR)
    ensure_dir(PROCESSED_DIR)
    ensure_dir(ERROR_DIR)
    ensure_dir(OUT_DIR)

    llm = LLMClient()
    
    logger.info("  CTI Pipeline 監控服務已啟動...")
    logger.info(f"  監控資料夾: {INPUT_DIR}")
    logger.info("按 Ctrl+C 可停止服務")

    try:
        while True:
            # 取得 input 資料夾內的所有 .txt
            files = [f for f in os.listdir(INPUT_DIR) if f.endswith(".txt")]
            
            if not files:
                time.sleep(5)
                continue
            
            for filename in files:
                src_path = os.path.join(INPUT_DIR, filename)
                
                try:
                    process_single_file(src_path, filename, llm)
                    
                    dest_path = os.path.join(PROCESSED_DIR, filename)
                    shutil.move(src_path, dest_path)
                    logger.info(f"  檔案已歸檔至: {dest_path}")
                    
                except Exception as e:
                    logger.error(f"  處理檔案 {filename} 時發生錯誤: {str(e)}")
                    error_dest_path = os.path.join(ERROR_DIR, filename)
                    shutil.move(src_path, error_dest_path)
                    logger.warning(f"  檔案已移至錯誤區: {error_dest_path}")

            time.sleep(1)

    except KeyboardInterrupt:
        logger.info("\n  服務已手動停止 (KeyboardInterrupt)")
    except Exception as e:
        logger.critical(f"  系統發生未預期錯誤: {e}")

if __name__ == "__main__":
    main()