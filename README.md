# CrackDB

## About
CrackDB is an open source project for building lookup tables of unsalted hashes allowing exceptionally fast password cracking. This project builds on the terrific work of [https://crackstation.net](crackstation) and makes several major improvements.

## Improvements on Crackstation
Crackstation is very well designed but can be cumbersome to use and maintain. This project set out with the aim of improving on many of these issues.

* Multithreading - CrackDB makes use of the powerful feature of multithreading and allows several hashes to be identified concurrently

+ Wordlist Expansion - CrackDB allows you to import additional words to an existing set of lookup tables meaning your database can grow. It is worth mentioning that existing entries will not be imported.

+ Pure Python - No more PHP! Python is a feature rich modern language with a large standard library. Everything in this project is written in pure python, simplifying deployment

+ In-built Web UI - Once a database is built, you can simply launch the script as a web UI to allow simple deployment

+ Compressed Wordlists - Once a database has been built, it is possible to compress the plaintext wordlists using gzip to save disk space

+ Efficient Design - The database is designed to be efficient in terms of storage space and memory consumption during lookup.

## Basic Usage
CrackDB is designed to be simple to use. At its most basic level you just need to build a database then do a lookup. This can be accomplished with the following commands:

```
mkdir ~/crackdb &&
python crackdb.py build ~/crackdb /usr/share/dict/words
```

Once this is built, you can perform a password lookup.

```
python crackdb.py crack ~/crackdb aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
```

Note that the strength of your database is entirely dependent on the wordlist it is created with. In this example, we have just used the OS wordlist.