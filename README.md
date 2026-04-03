# FavHunt

Fast favicon-based asset mapping and technology fingerprinting for Bug Bounty, OSINT, and Red Team operations.

## What It Does

FavHunt takes a list of URLs via stdin, fetches their `favicon.ico`, computes the MurmurHash3, and matches it against **1,400+ known technology fingerprints** to identify what software is behind each target. It groups assets by shared favicons, instantly revealing related infrastructure.

## Features

- **1,400+ Fingerprints** - Pre-loaded database covering CMS, firewalls, routers, cameras, admin panels, and more
- **Concurrent Scanning** - Multithreaded with configurable thread count (default: 20)
- **Technology Detection** - Automatic identification of web frameworks, network devices, and IoT systems
- **Shodan Dork Generation** - Instantly pivot to Shodan for internet-wide discovery
- **Clean Export** - Save grouped results to organized text files

## Installation

```bash
git clone https://github.com/yourusername/FavHunt.git
cd FavHunt
pip3 install -r requirements.txt
```

## Usage

```bash
# Basic scan using stdin
cat targets.txt | python3 favhunt.py

# Basic scan using a file list
python3 favhunt.py -l targets.txt

# 50 threads + export results
cat targets.txt | python3 favhunt.py -t 50 -o output/

# Generate Shodan dorks
cat targets.txt | python3 favhunt.py --shodan
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-l, --list` | File containing list of target URLs | None |
| `-t, --threads` | Number of concurrent threads | 20 |
| `-o, --output` | Directory to save grouped results | None |
| `--shodan` | Print Shodan dork queries | Off |

### Input Format

One URL per line, with or without `http://` or `https://` protocol:

```
https://example.com
https://sub.target.com
http://192.168.1.1
test.example.com
```


---

Inspired by [FavFreak](https://github.com/devanshbatham/FavFreak) by Devansh Batham.

## License

MIT
