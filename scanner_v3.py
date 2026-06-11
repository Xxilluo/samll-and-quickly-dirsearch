import argparse
import requests
import queue
import threading
import re
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

task_queue = queue.Queue()
print_lock = threading.Lock()

scan_results = []

EMAIL_REGEX = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
PHONE_REGEX = r'1[3-9]\d{9}'

def worker(target_url, headers, timeout, allow_redirects):
    while not task_queue.empty():
        try:
            path = task_queue.get(timeout=1)
        except queue.Empty:
            break
            
        full_url = target_url + path
        
        try:
            response = requests.get(
                full_url, 
                headers=headers, 
                timeout=timeout, 
                allow_redirects=allow_redirects,
                verify=False
            )
            if response.status_code in [200, 301, 302]:
                response.encoding = response.apparent_encoding 
                text_content = response.text        
                emails = list(set(re.findall(EMAIL_REGEX, text_content)))
                phones = list(set(re.findall(PHONE_REGEX, text_content)))
                result_data = {
                    "url": full_url,
                    "status": response.status_code,
                    "sensitive_info": {}
                }
                if emails: result_data["sensitive_info"]["emails"] = emails
                if phones: result_data["sensitive_info"]["phones"] = phones
                with print_lock:
                    print(f"[{response.status_code}] {full_url}")
                    if emails: print(f"    [-] 发现邮箱: {emails}")
                    if phones: print(f"    [-] 发现手机: {phones}")
                    scan_results.append(result_data)
                    
        except requests.exceptions.RequestException as e:
            pass 
        finally:
            task_queue.task_done()

def main():
    parser = argparse.ArgumentParser(description="Web 敏感资产高并发探测与审计工具 (Agent-Ready)")
    parser.add_argument("-u", "--url", required=True, help="目标 URL (例如: https://example.com)")
    parser.add_argument("-w", "--wordlist", default="dict.txt", help="字典文件路径")
    parser.add_argument("-t", "--threads", type=int, default=5, help="并发线程数")
    parser.add_argument("--timeout", type=int, default=3, help="网络请求超时时间(秒)")
    parser.add_argument("-o", "--output", default="result.json", help="结构化报告导出路径")
    args = parser.parse_args()   
    custom_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': '*/*'
    }
    paths = ["/index.php", "/user.php", "/config.json", "/robots.txt", "/api/v1/users"]
    for p in paths:
        task_queue.put(p)
    print(f"[*] 开始扫描目标: {args.url}")
    print(f"[*] 启动线程数: {args.threads}")
    print("-" * 40)
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(
            target=worker, 
            args=(args.url, custom_headers, args.timeout, False)
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()
        
    print("-" * 40)
    print(f"[*] 扫描结束，有效目标总数: {len(scan_results)}")
    if scan_results:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(scan_results, f, ensure_ascii=False, indent=4)
        print(f"[*] 结构化结果已保存至: {args.output}")

if __name__ == "__main__":
    main()