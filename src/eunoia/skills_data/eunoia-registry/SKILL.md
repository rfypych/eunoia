---
name: writeup-registry
description: How to query the Eunoia writeup registry over REST or MCP. Only test systems you have written authorization to test. The registry returns metadata plus links, never full text.
---

# Eunoia writeup registry

> **Authorization required:** only test systems you have written authorization to test. Reading a writeup is not permission to test a target.

## Calling the registry

REST base is `/v1`. Search with `GET /v1/search`, fetch one writeup with `GET /v1/writeups/{id}`, fetch its skill with `GET /v1/writeups/{id}/skill.md`, and check source health with `GET /v1/status`. Anonymous callers get 60 requests per minute and keyword search only; an API key raises the limit to 600 requests per minute and unlocks semantic and hybrid search.

Over MCP, use `search_writeups` to find candidates, `get_writeup` for one selected writeup, and `get_writeup_skill` for one technique you have decided to study in depth. `list_vuln_classes` and `list_programs` browse the corpus; `check_freshness` reports how current the index is.

## Lookup #1 vs Lookup #2

Lookup #1 runs after recon, before the attack plan: query once per technology in the target stack, limit 5 per technology, about 1000 to 1500 tokens per query. Lookup #2 runs mid-test, only when stuck or when a candidate needs verification: limit 3, at most 2 re-queries per hypothesis. For Lookup #2 pass mid_test=true to search_writeups (or lookup=mid_test on GET /v1/search) — that selects the mid-test ranking, which weighs technique similarity; without it every search uses the pre-test ranking. Never use limit 20 inside the loop.

## Token limits

A search result list is the cheapest layer: one short object per result, excerpt at most 300 characters. A full writeup object is only for one selected writeup. A SKILL.md is only for one technique you will execute, under 5000 tokens. Full text of the original article never enters the context: follow the canonical link instead.

Track seen writeup ids per run and never fetch the same id twice. After 3 probes with no new signal, stop and re-query once, then mark the hypothesis debunked.

## berlatih dengan aman

Practice this technique only in a lab (PortSwigger Academy, DVWA, HackTheBox, TryHackMe, or an in-scope bug bounty program that explicitly allows the technique). Only test systems you have written authorization to test. Reading a writeup is not permission to test a target.
