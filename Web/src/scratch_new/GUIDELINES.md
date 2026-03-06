Use the following prompt in a new chat. It is structured to give full technical context, research objective, completed work, and expected next steps.

---

**PROMPT TO USE IN NEW CHAT**

I am a final-year cybersecurity student working on my FYP titled:

“IndexedDB Dynamic Taint Analysis for Detecting Persistent Web Tracking Mechanisms.”

My research is inspired by the paper:
“I Know What You Did Last Summer: New Persistent Tracking Mechanisms in the Wild.”

Objective:
We want to detect and analyze persistent tracking mechanisms that use IndexedDB instead of cookies, especially third-party cross-site tracking.

What we have already completed:

1. Used Google BigQuery with the HTTP Archive dataset.

2. Queried `httparchive.crawl.requests`.

3. Detected IndexedDB usage using this regex:

   indexedDB.open|indexedDB.deleteDatabase|IDBTransaction|IDBObjectStore

4. Identified:

   * First-party IndexedDB usage
   * Third-party IndexedDB usage
   * Script domains using IndexedDB across multiple websites

5. Extracted top script domains using IndexedDB.

6. Ran out of BigQuery credits.

Current status:
We have completed the large-scale measurement phase.
We now want to implement the dynamic analysis phase locally.

What we want to build next:

* A system that detects when a website:

  1. Generates an identifier
  2. Stores it in IndexedDB
  3. Retrieves it later
  4. Sends it to a tracking server

We want:

* Step-by-step implementation guidance
* Clear architecture design
* Practical tools (Playwright / Selenium / instrumentation)
* Methodology aligned with academic research
* How to distinguish legitimate IndexedDB usage from tracking

Please guide me step-by-step starting from where we left off, assuming:

* No more BigQuery access
* Limited computing resources
* Need to produce publishable research results
