# 🧭 PathFinder-project
<p align="center">
  <b>Advanced Ethical Path Discovery Tool for Bug Bounty Hunters</b><br>
  <i>Developed with ❤️ by <a href="https://github.com/RootHunter">RootHunter</a></i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20MacOS-green?style=for-the-badge&logo=linux" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" />
</p>

---

## ⚡ Overview

**PathFinder** is an **ethical penetration testing helper** written in Python, designed to assist **bug bounty hunters** and **security researchers** in discovering **hidden paths, endpoints, and directories** within target web applications — safely and efficiently.

This project contains **two versions**:
- 🖥️ **GUI Edition:** A graphical interface for easy use and visualization.  
- 💻 **CLI Edition:** A colorful terminal version for professionals and automation.

> ⚠️ This tool is for **authorized security testing** and **educational purposes only**.  
> Do **not** use it on systems without explicit permission.

---

## ✨ Features

✅ Multi-threaded asynchronous scanning for speed  
✅ Supports custom wordlists or built-in intelligent lists  
✅ Extracts endpoints from `robots.txt` and `sitemap.xml`  
✅ Color-coded output by HTTP status codes  
✅ Exports results in JSON format  
✅ GUI interface (Tkinter-based) + Terminal edition  
✅ Lightweight, portable, and open-source  

---

## 🧩 Tech Stack

- **Language:** Python 3.9+
- **Core Libraries:** `aiohttp`, `asyncio`, `tqdm`, `colorama`, `beautifulsoup4`
- **GUI:** `Tkinter`
- **Output Formats:** JSON / Console  

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/root-hun-ter/PathFinder-project
cd PathFinder-project

# Install dependencies
pip install -r requirements.txt
```

If you don’t have a `requirements.txt`, you can install manually:
```bash
pip install aiohttp tqdm colorama beautifulsoup4
```

---

## 💻 Usage

### ▶️ Terminal (CLI) Edition

```bash
python pathfinder.py https://example.com
```

With custom wordlist:
```bash
python pathfinder.py https://target.com -w wordlist.txt -c 20
```

Output:
```
[200] https://example.com/admin
[301] https://example.com/login
[403] https://example.com/.git/
```

Results will be saved automatically in:
```
out/example.com_results.json
```

---

### 🖥️ GUI Edition

Simply run:
```bash
python pathfinder_gui.py
```

Then enter your target domain, choose a wordlist, and start scanning —  
results will appear directly inside the graphical window.

---

## 🎨 Screenshot (Preview)

<p align="center">
  <img src="https://github.com/root-hun-ter/PathFinder-project/gui-preview.png" width="80%" alt="GUI Preview" />
</p>

---

## ⚙️ Example Features in Action

| Feature | Description |
|----------|--------------|
| 🌐 URL Fuzzing | Fast concurrent directory and endpoint discovery |
| 🤖 robots.txt Parser | Extracts disallowed paths for potential endpoints |
| 🗺️ Sitemap Scanner | Reads and extracts all indexed links |
| 🎨 Color-Coded Output | Instantly distinguish between 200, 301, 403, 404 |
| 📁 Export Results | Save as JSON for reporting or analysis |

---

## 🧑‍💻 Developer

**By RootHunter**  
> 🐙 GitHub: [github.com/RootHunter](https://github.com/root-hun-ter)  
> 📘 Facebook: [facebook.com/RootHunter](https://www.facebook.com/roothunter404)  
> 📷 Instagram: [@roothunter](https://instagram.com/_root_hunter_)  


---

## 🛡️ Legal Disclaimer

This project is **strictly for ethical hacking, security research, and authorized testing** only.  
The developer is **not responsible** for any misuse or illegal activities performed using this tool.

---

## 🪪 License

Released under the [MIT License](LICENSE).

---

## 🌟 Support the Project

If you find **PathFinder** useful, consider giving it a ⭐ on GitHub —  
your support motivates future development 🚀
