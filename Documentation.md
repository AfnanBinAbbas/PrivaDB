# PrivaDB: Core Engine Architecture & Algorithmic Deep-Dive

This document isolates the internal mechanics of the PrivaDB extraction, measurement, and classification systems. It assumes prior knowledge of the deployment topology described in the main project file.

## ⚙️ Core Engine Internals

The analysis core leverages a multi-threaded, asymmetric architecture to safely isolate target sites while intercepting browser-level APIs.

### The Playwright Crawler Injector (`crawler.py`)
Rather than relying on post-execution static analysis, PrivaDB performs **Dynamic Taint Tracking**. During page initialization (`page.add_init_script`), the crawler injects an asynchronous JavaScript probe. 
- **Method Override**: Native `window.indexedDB.open` requests are intercepted to map the database schema before site scripts execute.
- **Atomic Cancellation**: A strictly enforced `Zero-Tolerance Cancellation` mechanism ensures that if a timeout occurs at *any* stage of page navigation or IDB resolution, the specific browser instance is immediately reaped utilizing `psutil` signal isolation. This eradicates "ghost processes" and guarantees zero memory leaks across consecutive heavy scans.

### Schema Resolution & Capping
Once injected, the probe enumerates all available databases via the experimental `indexedDB.databases()` API (with fallbacks for legacy implementations).
To prevent intentional OOM (Out-of-Memory) attacks from malicious sites, extraction limits are enforced:
- Maximum records processed per Object Store: **200**
- Maximum depth stringification: **5 levels**
- Transactions are strictly enforced as `readonly`.

## 🔬 Precision Taint Heuristics

Data is not inherently treated as an identifier. The classification pipeline (`cookieSwapPartyHeuristics.py` equivalence logic) applies deterministic filtering to reduce false positives.

### 1. Entropy Validation (The Shannon Filter)
Randomness is the primary indicator of a tracker ID. PrivaDB calculates Shannon Entropy for every extracted string:
```python
def calculate_entropy(data: str) -> float:
    # Calculates bits of information per character
    probabilities = [float(data.count(c)) / len(data) for c in dict.fromkeys(list(data))]
    return -sum(p * math.log(p) / math.log(2.0) for p in probabilities)
```
- **Threshold (`ENTROPY_THRESHOLD`)**: Strings yielding `< 3.0 bits` of entropy are discarded (e.g., standard words like "true", "admin", "theme_light").
- **Length Gate (`MIN_ID_LENGTH`)**: Strings shorter than 8 characters are ignored, adhering to standard UID generation probabilities.

### 2. Format Exclusion
Prior to entropy calculation, strings are evaluated against pre-compiled regex arrays to exclude known structural benign data (dates, localized timestamps, generic structural booleans).

## 📡 The Exfiltration Detection Matrix

Once high-entropy identifiers are isolated from the IndexedDB stores, the engine cross-references this dataset against the intercepted network traffic graph.

### Network Interception Layer
All outbound requests are parsed in real-time. The payload inspector recursively searches for the presence of the IDB strings within:
1. **Request Origins / query parameters**: (`?user_id=...`)
2. **POST/PUT Data Bodies**: JSON, URL-Encoded, and Form-Data payloads.
3. **Cookie Headers**: Secondary exfiltration where trackers persist IDB values into HTTP-only tracking cookies.

### Classification State-Machine
Matches trigger the creation of an `Exfiltration Event`.
- **Constraint Matrix**: If the destination domain matches the origin, it is logged as an *Internal State Transfer*. If the destination domain differs, it triggers the *Third-Party Exfiltration* flag.
- **Tracker Validation**: The destination domain is checked against the internal SQLite tracker matrix (merged from Disconnect, EasyList, and custom intelligence). A match elevates the event to a `High Confidence Tracking Violation`.

## 🦊 The Foxhound Submodule

When executed in `firefox` mode, PrivaDB can engage the SAP SE **Foxhound** engine.
Unlike the Chromium heuristic approach which relies on payload inspection, Foxhound utilizes native C++ level memory-tagging within the Firefox Javascript engine (SpiderMonkey). 
- Variables read from IDB are physically "tainted" in memory.
- If that specific memory pointer is passed to an `XMLHttpRequest` or `fetch` sink, the browser compiles an irrefutable taint report.
- PrivaDB serves as the aggregation and UI translation layer for these lower-level C++ taint triggers.
