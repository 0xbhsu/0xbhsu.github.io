---
layout: blank
---
#!/usr/bin/python3
from colorama import Fore, Style
from datetime import datetime
from tqdm import tqdm
import requests
import asyncio
import aiohttp
import json
import sys
import os



SQLMAP_SERVER_IP = "http://127.0.0.1"  # change this
SQLMAP_SERVER_PORT = 1337  # and this
RESULTS_DATA = {"results": []}  # dict to store the results



class TaskProcessor:
    def __init__(self, task, progress_bar):
        self._TASK_ID = task["task_id"]
        self._TASK_URL = task["task_url"]
        self._SLEEP_TIME = 15
        self._PB = progress_bar
        self.__SESSION = aiohttp.ClientSession()
        self.__API_SCAN_URL = f"{SQLMAP_SERVER_IP}:{SQLMAP_SERVER_PORT}/scan/{self._TASK_ID}"

    async def __fetch_status(self):
        async with self.__SESSION.get(f"{self.__API_SCAN_URL}/status") as response:
            return await response.json()

    async def __fetch_data(self):
        async with self.__SESSION.get(f"{self.__API_SCAN_URL}/data") as response:
            return await response.json()

    async def close_session(self):
        await self.__SESSION.close()

    async def process_task(self):
        while True:
            task_status = await self.__fetch_status()
            if task_status["status"] == "terminated":
                task_data = await self.__fetch_data()
                is_vuln = False if not len(task_data["data"]) else True
                result = {"url": self._TASK_URL, "is_vuln": is_vuln, "vectors": []}
                if is_vuln:
                    for data in task_data["data"]:
                        if data["type"] == 1:
                            for attack_vector in data["value"][0]["data"].values():
                                result["vectors"].append({"vector_title": attack_vector["title"], "vector_payload": attack_vector["payload"]})
                            break
                RESULTS_DATA["results"].append(result)
                self._PB.update(1)
                break
            await asyncio.sleep(self._SLEEP_TIME)



async def runner(size_pbar):
    print(f" [*] {Fore.YELLOW}Parsing tasks...{Style.RESET_ALL}")
    with tqdm(total=size_pbar, leave=False) as pbar:
        SCAN_TASKS = [TaskProcessor(task, pbar) for task in TASKS]  # creating API fetching for every task
        await asyncio.gather(*[scan_task.process_task() for scan_task in SCAN_TASKS])  # processing every task
        await asyncio.gather(*[scan_task.close_session() for scan_task in SCAN_TASKS])  # closing async HTTP session



if __name__ == "__main__":
    TASKS = []
    RESULTS_FILENAME = f"report-{datetime.now().strftime('%d-%m-%Y_%H-%M')}.json"
    try:
        TARGETS_FILE = sys.argv[1]
        if not os.path.isfile(TARGETS_FILE):
            print("Targets file not found!")
            exit(1)
        with open(TARGETS_FILE, "r", encoding="utf-8") as f:
            TARGETS_JSON = json.loads(f.read())
    except IndexError:
        print("Usage: ./processor.py targets.json")
        exit(1)

    # Creating/starting tasks
    print(f" [*] {Fore.YELLOW}Creating and starting tasks...{Style.RESET_ALL}")
    for target in TARGETS_JSON:
        # using requests lib here instead of aiohttp because there's no need
        task_id = requests.get(f"{SQLMAP_SERVER_IP}:{SQLMAP_SERVER_PORT}/task/new").json()["taskid"]  # generate a new taskID
        TASKS.append({"task_id": task_id, "task_url": target["url"]})  # appending to the task list
        data = {"threads": 10, "risk": 3, "level": 5}
        for arg, value in target.items():  # parsing options from the file to use in the API
            data[arg] = value if len(value) else None
        # starting the task
        r = requests.post(f"{SQLMAP_SERVER_IP}:{SQLMAP_SERVER_PORT}/scan/{task_id}/start", json=data, headers={"Content-Type": "application/json"}).json()
        print(f" [-] {Fore.YELLOW}Task created and started ({Fore.CYAN}{task_id}{Fore.YELLOW}){Style.RESET_ALL}")

    # Starting the async API fetching
    asyncio.run(runner(len(TASKS)))

    # Writing results to file
    print(f" [+] {Fore.GREEN}Scan completed! Saving data to file {Fore.CYAN}{RESULTS_FILENAME}{Style.RESET_ALL}")
    with open(RESULTS_FILENAME, "w", encoding="utf-8") as f:
        json.dump(RESULTS_DATA, f, indent=4)
    
    # Printing the results aswell
    for result in RESULTS_DATA["results"]:
        if result['is_vuln']:
            print(f"  > {Fore.RED}{result['url']} (vulnerable){Style.RESET_ALL}")
            for i in result["vectors"]:
                print(f"     * {i['vector_title']}")
        else:
            print(f"  > {Fore.YELLOW}{result['url']} (not vulnerable){Style.RESET_ALL}")