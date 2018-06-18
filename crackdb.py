import os
import sys
import hashlib
import argparse
import multiprocessing
import re
import struct
import binascii
import gzip
import time
import Queue
import signal
# Import our large binary file sorting library
from binarydb import *
import webserver

WORDLIST_NAME = 'wordlist{:04x}'
HASHFILE_NAME = '{:s}{:02x}'
LOOKUPFILE_NAME = 'lut'
PRINT_LOCK = multiprocessing.Lock()
UNSORTED_APPEND = 'u'
APPENDED_APPEND = 'z'

# These values affect the maximum length and index format
# Reducing the HASHLEN value will reduce the database size at the cost of
#   more collisions during lookup, and thus more time spent resolving hashes
# Tweaking the WIDTHBITS value will adjust the hard maximum input length
#   at the cost of additional seeking and failed attempts during lookup
#   HOWEVER, this is a reasonable trade given the aim of a lookup table to
#   allow the cracking of very large hashes that you would not normally be
#   able to brute force
HASHLEN = 6
WIDTHBITS = 6
# These values are calculated. Do not touch!
INDEXBITS = 32-WIDTHBITS
WIDTHMASK = ((1<<WIDTHBITS)-1)
INDEXMASK = ((1<<INDEXBITS)-1)
MAXINDEX = (2**WIDTHBITS)
RECORDSIZE = HASHLEN+4

def algoSha1(word):
    return hashlib.sha1(word).digest()
def algoSha256(word):
    return hashlib.sha256(word).digest()
def algoSha384(word):
    return hashlib.sha384(word).digest()
def algoSha512(word):
    return hashlib.sha512(word).digest()
def algoMd5(word):
    return hashlib.md5(word).digest()
def algoNTLM(word):
    try: return hashlib.new('md4', word.encode('utf-16le')).digest()
    except UnicodeDecodeError: return hashlib.new('md4', word.decode('ascii', 'ignore').encode('utf-16le')).digest()
def algoMySQL41(word):
    return hashlib.sha1(hashlib.sha1(word).digest()).digest()
def algoMd5Md5Hex(word):
    return hashlib.md5(hashlib.md5(word).hexdigest()).digest()
ALGORITHM = {'sha1' : algoSha1,
             'sha256' : algoSha256,
             'sha384' : algoSha384,
             'sha512' : algoSha512,
             'md5' : algoMd5,
             'ntlm' : algoNTLM,
             'mysql41' : algoMySQL41,
             'md5md5hex' : algoMd5Md5Hex}
EMPTYHASH = {a:ALGORITHM[a]('') for a in ALGORITHM}
ALGOSIZES = {a:len(EMPTYHASH[a]) for a in ALGORITHM}
EMPTYLUT = {EMPTYHASH[a]:a for a in EMPTYHASH}

def getAlgorithms(location):
    '''
    Return a list of algorithms generated in the location
    '''
    return [a for a in ALGORITHM if os.path.isdir(os.path.join(location, a))]

CACHED_MAXSIZE = None
def maxWordsize(location, cache=True):
    '''
    Internal function to enumerate the largest wordsize currently
    sorted in the database.
    '''
    global CACHED_MAXSIZE
    if cache and CACHED_MAXSIZE != None:
        return CACHED_MAXSIZE
    # Return None if there are none
    if len(os.listdir(os.path.join(location, 'wordlists'))) == 0:
        return None
    lastfile = sorted(os.listdir(os.path.join(location, 'wordlists')))[-1]
    m = re.match(r'wordlist([0-9a-f]+)(?:\.[gx]z)?$', lastfile)
    if m is None:
        raise Exception('Unable to find maximum word size')
    CACHED_MAXSIZE = int(m.group(1), 16)
    return CACHED_MAXSIZE

def getWordlist(location, index, openmode=None, bufsize=-1, compress=False):
    global WORDLIST_NAME
    filename = WORDLIST_NAME.format(index)
    filepath = os.path.join(location, 'wordlists', filename)
    if not os.path.isfile(filepath) and (os.path.isfile('{:s}.gz'.format(filepath)) or compress):
        filepath = '{:s}.gz'.format(filepath)
    if openmode is None:
        return filepath
    # Handle gzip compressed files
    # This will default to level 9
    if filepath.endswith('.gz'):
        return gzip.GzipFile(filepath, openmode)
    return open(filepath, openmode, bufsize)

def getWordlists(location, openmode=None):
    for width in xrange(1, maxWordsize(location)):
        yield getWordlist(location, width, openmode=openmode)

def getHashfile(location, algorithm, index, openmode=None, bufsize=-1):
    global HASHFILE_NAME
    filename = HASHFILE_NAME.format(algorithm, index)
    filepath = os.path.join(location, algorithm, filename)
    if not os.path.isfile(filepath):
        if os.path.isfile(filepath + APPENDED_APPEND):
            filepath += APPENDED_APPEND
        else:
            filepath += UNSORTED_APPEND
    if openmode is None:
        return filepath
    return open(filepath, openmode, bufsize)

def getUnsortedFiles(location):
    global HASHFILE_NAME, ALGORITHM
    for algorithm in sorted(ALGORITHM.keys()):
        for index in xrange(256):
            basefilepath = os.path.join(location, algorithm, HASHFILE_NAME.format(algorithm, index))
            unsortedpath = basefilepath + UNSORTED_APPEND
            if os.path.isfile(unsortedpath):
                yield unsortedpath
            appendedpath = basefilepath + APPENDED_APPEND
            if os.path.isfile(appendedpath):
                yield appendedpath

def markAlgorithmUnsorted(location, algorithm):
    global HASHFILE_NAME
    count = 0
    for index in xrange(256):
        basefilepath = os.path.join(location, algorithm, HASHFILE_NAME.format(algorithm, index))
        unsortedpath = basefilepath + UNSORTED_APPEND
        if os.path.isfile(basefilepath):
            os.rename(basefilepath, unsortedpath)
            count += 1
    return count
def markAlgorithmsUnsorted(location, algorithms):
    count = 0
    for algorithm in algorithms:
        count += markAlgorithmUnsorted(location, algorithm)
    return count

def hasUnsortedTables(location):
    for algorithm in getAlgorithms(location):
        algpath = os.path.join(location, algorithm)
        for table in os.listdir(algpath):
            if table[-1] == UNSORTED_APPEND:
                return True
    return False

def markAlgorithmsAppended(location):
    for algorithm in getAlgorithms(location):
        for index in xrange(256):
            basefilepath = os.path.join(location, algorithm, HASHFILE_NAME.format(algorithm, index))
            appendedpath = basefilepath + APPENDED_APPEND
            if os.path.isfile(basefilepath):
                os.rename(basefilepath, appendedpath)

stats = None
def readWordlists(wordlists, maxsize=None, ignore=None, wordfilter=None, analysis=False, count=None):
    # Analysis dictionary
    global stats
    stats = {'total':0, 'ignored':0, 'filtered':0, 'toobig':0, 'maxlength':0, 'lengths':{}, 'output':0}
    spinner, state = '|/-\\', 0
    for wordlist in wordlists:
        fh = open(wordlist, 'rU') if wordlist != '-' else sys.stdin
        for line in fh:
            line = line.strip()
            if count != None and stats['output'] >= count:
                break
            # We dont store zero or one length
            if line == '':
                continue
            # Update our length stats
            if len(line) not in stats['lengths']:
                stats['lengths'][len(line)] = 0
            stats['lengths'][len(line)] += 1
            # Add to toal
            stats['total'] += 1
            # Check if it is too big
            if maxsize != None and len(line) > maxsize:
                stats['toobig'] += 1
                continue
            # Check if it adheres to our filter
            if wordfilter != None and re.match(wordfilter, line) is None:
                stats['filtered'] += 1
                continue
            # Check if it should be ignored
            if ignore != None and re.match(ignore, line) != None:
                stats['ignored'] += 1
                continue
            # Update our maximum size
            if len(line) > stats['maxlength']:
                stats['maxlength'] = line
            # Yield if not doing analysis wanted
            stats['output'] += 1
            if stats['output'] % 10000 == 0:
                with PRINT_LOCK:
                    sys.stdout.write('\r[{:s}] Words: {:,}'.format(spinner[state%len(spinner)], stats['output']))
                    state += 1
                    sys.stdout.flush()
            yield line
        if wordlist != '-':
            fh.close()

def wordlistinfo(wordlists, maxsize=None, ignore=None, wordfilter=None):
    '''
    Main entrypoint for the wordlistinfo function
    Performs a simple analysis of the wordlists (and any constraints)
    in order to indicate what a resultant wordlist may comprise
    '''
    print('[+] Analysing wordlists')
    print('[+] Filter regex: {:s}'.format(wordfilter if wordfilter != None else 'unset'))
    print('[+] Ignore regex: {:s}'.format(ignore if ignore != None else 'unset'))
    print('[+] Maximum size: {:d}'.format(maxsize))
    print('[+] Begining Analysis...')
    for word in readWordlists(wordlists, maxsize=maxsize, ignore=ignore, wordfilter=wordfilter, analysis=True):
        pass
    print('\r[+] Words in wordlists: {:d}'.format(stats['total']))
    print('[+] Words above max:    {:d}'.format(stats['toobig']))
    print('[+] Words ignored:      {:d}'.format(stats['ignored']))
    print('[+] Length analysis:')
    for length in stats['lengths']:
        print('[+]\t{:2d}: {:d}'.format(length, stats['lengths'][length]))

def getWords(location, size=None):
    '''
    Internal function to parse out the wordlists
    '''
    for filename in sorted(os.listdir(os.path.join(location, 'wordlists'))):
        m = re.match('wordlist([0-9a-f]+)$', filename)
        if m is None:
            continue
        wordsize = int(m.group(1), 16)
        if size != None and wordsize != size:
            continue
        with getWordlist(location, wordsize, 'rb') as fh:
            index = 0
            while True:
                word = fh.read(wordsize)
                if not word:
                    break
                yield (wordsize, index, word,)
                index += 1

def compareRecords(record1, record2):
    return memcmp(record1[:HASHLEN], record2[:HASHLEN])


class DelayedKeyboardInterrupt(object):

    def __init__(self, dropout):
        self.dropout = dropout
        self.printlock = multiprocessing.Lock()
        self.signal_received = None
        self.old_handler = None

    def __enter__(self):
        self.signal_received = False
        self.old_handler = signal.signal(signal.SIGINT, self.handler)

    def handler(self, sig, frame):
        self.signal_received = (sig, frame)
        with self.printlock:
            if not self.dropout.is_set():
                print('\r[+] Stop sorting requested')
        self.dropout.set()
        

    def __exit__(self, exittype, value, traceback):
        signal.signal(signal.SIGINT, self.old_handler)
        # if self.signal_received:
        #   self.old_handler(*self.signal_received)

def sortUnsortedFileWorker(filename):
    # We use force mmap because there will be multiple
    # files being sorted at once meaning we will likely
    # require a lot of ram. This prevents us paging
    return sortFile(filename, RECORDSIZE, compareRecords, threads=1, algorithm='quick', rename=filename[:-1], forcemmap=True)

def sortAppendedFileWorker(filename):
    return sortFile(filename, RECORDSIZE, compareRecords, threads=1, algorithm='bubble', rename=filename[:-1], forcemmap=True)

def sortDatabase(location, threads=None, count=None):
    '''
    Entrypoint to the sort comand line option. Sorts all available hash databases
    '''
    # If we have unsorted files and enough threads we
    # can paralellise sorting them. We do this because
    # quicksort spends lots of time in one thread so we
    # may as well just do more files
    unsortedFiles = [f for f in getUnsortedFiles(location) if f[-1] == UNSORTED_APPEND]
    appendedFiles = [f for f in getUnsortedFiles(location) if f[-1] == APPENDED_APPEND]
    if (len(unsortedFiles) > 1 or len(appendedFiles) > 1) and threads >= 2:
        dropout = multiprocessing.Event()
        with DelayedKeyboardInterrupt(dropout):
            p = multiprocessing.Pool(threads)
            p.map(sortUnsortedFileWorker, unsortedFiles)
            p.map(sortAppendedFileWorker, appendedFiles)

    # Now we do the linear sorting techniques as a catch-all
    for filename in getUnsortedFiles(location):
        if count != None and count == 0:
            break
        # Skip zero or one record length files
        if os.path.getsize(filename) in (0, RECORDSIZE,):
            os.rename(filename, filename[:-1])
            continue
        dropout = multiprocessing.Event()
        with DelayedKeyboardInterrupt(dropout):
            # For import mode, we use bubble sort as it is more
            # efficient for appended records due to the bubble
            # up technique
            sortmethod = 'quick' if filename[-1] == UNSORTED_APPEND else 'bubble'
            # print('[+] Sorting {:s} using {:s} sort algorithm'.format(os.path.basename(filename), sortmethod))
            sortFile(filename, RECORDSIZE, compareRecords, threads=threads, algorithm=sortmethod, rename=filename[:-1])
            if count != None:
                count -= 1
            if dropout.is_set():
                print('[+] User requested stop')
                print('[!] Database may remain unsorted')
                break

def importwords(location, wordlists=None, maxsize=None, ignore=None, wordfilter=None, count=None, threads=None, importmode=False):
    ''' 
    The main entry point for build, import and add.
    This is responsible for building up the cracking database given a wordlist.
    It also handles the entrypoint for add for adding new algorithms to an existing
    database. In this instance, the wordlists argument is left as None.
    '''

    def writeWorker(wordqueue, writequeue, complete):
        '''
        The writing worker process for adding words to a database.
        This function handles caching of the data before writing. It is often best to have
        a small cache. If the cache size if too large, then processing blocks up on IO
        For common sized wordlist files (typically less than 100), we can rely on the stdlib
        cache by maintaining a list of open file handles.
        '''
        def flushWordBuffers():
            for width in wordBuffers:
                with getWordlist(args.location, width, openmode='ab+', bufsize=0) as fh:
                    fh.write(wordBuffers[width])
                wordBuffers[width] = ''
        def flushHashBuffers():
            for algorithm in hashBuffers:
                for hashindex in xrange(len(hashBuffers[algorithm])):
                    with getHashfile(args.location, algorithm, hashindex, openmode='ab+', bufsize=0) as fh:
                        fh.write(hashBuffers[algorithm][hashindex])
                    hashBuffers[algorithm][hashindex] = ''
        
        # Build out initial indexes table
        file_indexes = {}
        if maxWordsize(location) != None:
            for width in xrange(1, maxWordsize(location)):
                wordlist = getWordlist(location, width)
                file_indexes[width] = (os.path.getsize(wordlist) / width) if os.path.isfile(wordlist) else 0
        
        # Initialise out write buffers
        wordBuffers = {}
        hashBuffers = {algorithm:['' for i in xrange(256)] for algorithm in args.algorithm}
        cachedHandles = {w:getWordlist(args.location, w, openmode='ab+') for w in xrange(3, 100)} if wordlists != None else {}
        blocksize = 8192

        while not writequeue.empty() or not wordqueue.empty() or not complete.is_set():
            try:
                index, word, hashdict = writequeue.get(True, 1)
            except Queue.Empty:
                time.sleep(0.5)
                continue
            width = len(word)
            # Append the word to the word buffer
            # Only write to the wordlist files if we are not adding a new algo
            if wordlists != None:
                # See if we have a cached file handle for common widths. If we do, use it
                # and allow the system to handle write buffers. If not, update our own buffers
                if width in cachedHandles:
                    cachedHandles[width].write(word)
                else:
                    if width not in wordBuffers:
                        wordBuffers[width] = ''
                    wordBuffers[width] += word
                    # Check if we need to flush
                    if len(wordBuffers[width]) > blocksize:
                        with getWordlist(args.location, width, openmode='ab+', bufsize=0) as fh:
                            fh.write(wordBuffers[width])
                        wordBuffers[width] = ''
                # Increment the index
                if width not in file_indexes:
                    file_indexes[width] = 0
                index = file_indexes[width]
                file_indexes[width] += 1
            # Append the hash to the hash buffers
            for algorithm in hashdict:
                hashbytes = hashdict[algorithm]
                # n bits | 32-n bits
                # width    index
                offsetval = ((width&WIDTHMASK) << INDEXBITS) | (index & INDEXMASK)
                hashindex = ord(hashbytes[0])
                hashBuffers[algorithm][hashindex] += hashbytes[:HASHLEN] + struct.pack('>I', offsetval)
                if len(hashBuffers[algorithm][hashindex]) > blocksize:
                    with getHashfile(args.location, algorithm, hashindex, openmode='ab+', bufsize=0) as fh:
                        fh.write(hashBuffers[algorithm][hashindex])
                    hashBuffers[algorithm][hashindex] = ''

        # Make sure we flush the remaining buffers
        if wordlists != None:
            for width in cachedHandles:
                # Flush and close handles to be dilligent
                cachedHandles[width].flush()
                cachedHandles[width].close()
            flushWordBuffers()
        flushHashBuffers()

    def hashWorker(wordqueue, writequeue, complete):
        '''
        The hashing worker process for building a database.
        This function takes new words from the _wordqueue_, hashes them
        Then puts them into the writequeue for writing to file
        '''
        # We cache the open file handles. This is ok because we always grab the mutex
        # before we do a write. Additionally, the files are open for append which guarantees
        # that we will only ever write to the end of the file
        while not wordqueue.empty() or not complete.is_set():
            try:
                word = wordqueue.get(True, 1)
            except Queue.Empty:
                time.sleep(0.5)
                continue
            index = None
            if isinstance(word, tuple):
                index, word = word

            # Output the hash to each of the lookup tables
            hashdict = {algorithm:ALGORITHM[algorithm](word) for algorithm in args.algorithm}
            job = (index, word, hashdict,)
            writequeue.put(job)

    if threads is None:
        threads = multiprocessing.cpu_count()

    # Set up the wordlists folder
    wordlistDir = os.path.join(location, 'wordlists')
    if not os.path.isdir(wordlistDir):
        os.mkdir(wordlistDir)
    existingAlgorithms = getAlgorithms(location)
    for algorithm in args.algorithm:
        hashdir = os.path.join(location, algorithm)
        if os.path.isdir(hashdir) and importmode is False:
            print('[!] ERROR: Hash algorithm {:s} already exists'.format(algorithm))
            return
        elif not os.path.isdir(hashdir):
            os.mkdir(hashdir)

    complete = multiprocessing.Event()
    wordqueue = multiprocessing.Queue(10000)
    writequeue = multiprocessing.Queue(10000)

    writer = multiprocessing.Process(target=writeWorker, args=(wordqueue, writequeue, complete,))
    writer.daemon = True
    writer.start()

    workers = []
    for i in xrange(threads):
        p = multiprocessing.Process(target=hashWorker, args=(wordqueue, writequeue, complete,))
        p.daemon = True
        p.start()
        workers.append(p)

    try:
        if wordlists != None:
            print('[+] Creating wordlist and hash tables' if importmode is False else '[+] Importing additional words to database')
            print('[+] Building: {:s}'.format(', '.join(args.algorithm)))
            for word in readWordlists(wordlists, maxsize=maxsize, ignore=ignore, wordfilter=wordfilter, count=count):
                wordqueue.put(word)
        else:
            print('[+] Adding new algorithm(s) to database')
            # Remove any that we already have
            args.algorithm = [a for a in args.algorithm if a not in existingAlgorithms]
            print('[+] Adding: {:s}'.format(', '.join(args.algorithm)))
            # Just adding a new algorithm
            for wordsize, index, word in getWords(location):
                wordqueue.put((index, word,))
    except KeyboardInterrupt:
        print('\r[+] Interrupted. During wordlist build')
        # We need to empty the queues to allow the children to exit
        while not wordqueue.empty():
            wordqueue.get(True, 1)
        while not writequeue.empty():
            writequeue.get(True, 1)
        return
    finally:
        print('\r[+] Killing workers')
        complete.set()
        for i in xrange(threads):
            workers[i].join()
        writer.join()

    print('\r[+] Building wordlist complete')

    # Sort the hash databases
    print('[+] Sorting hash database files')
    return sortDatabase(location, threads=threads)

def lookup(location, hashbytes, available):
    '''
    This is the main lookup algorithm so needs to be as efficient as possible.
    This needs to be the fastpath; no unnecessary computation or repeated computation
    '''
    def detectAlgo(hashbytes, available):
        for algorithm in available:
            if len(hashbytes) == ALGOSIZES[algorithm]:
                yield algorithm
    maxsize = maxWordsize(location)
    for algorithm in detectAlgo(hashbytes, available):
        hashfile = getHashfile(location, algorithm, ord(hashbytes[0]))
        assert(os.path.isfile(hashfile))
        if hashfile[-1] in (UNSORTED_APPEND, APPENDED_APPEND,):
            sys.stderr.write('[!] Unsorted database! Unable to crack {:s}\n'.format(algorithm))
            continue
        # Step 1: Open the hash database file which matches the hash in question
        with open(hashfile, 'r+b') as fh:
            results = binarySearch(fh, hashbytes[:HASHLEN], width=RECORDSIZE)
            for result in results:
                # Parse out the lookup width and index
                index = struct.unpack('>I', result[-4:])[0]
                width = index >> INDEXBITS
                if width == 0:
                    width = MAXINDEX
                offset = index & INDEXMASK
                # Because we may need to wrap, we keep looking until we find a match in the wordlists
                while width < maxsize:
                    with getWordlist(location, width, 'rb') as fh:
                        # The offset will wrap for large wordlists so we need to keep seeking and checking
                        fh.seek(width * offset, os.SEEK_CUR)
                        while True:
                            word = fh.read(width)
                            if word == '' or word is None:
                                break
                            if ALGORITHM[algorithm](word) == hashbytes:
                                return algorithm, word
                            fh.seek(width * INDEXMASK, os.SEEK_CUR)
                    # We didnt find a matching word so we increase the wordsize
                    width += MAXINDEX
    return None

def storeUncrackable(location, hashstr):
    '''
    This is a handler method for dealing with uncrackable hashes.
    By default they are ignored, but they can be saved to a text file
    in the database folder
    '''
    with open(os.path.join(location, 'uncrackable.txt'), 'at') as fh:
        fh.write('{:s}\n'.format(hashstr))

def crack(location, hashes, threads=None, uncrackable=None):
    '''
    Main entry point to the crack command line option.
    Takes the location of the database and an iterable containing
    hash strings or file paths. If an entry contains a file path it
    is opened and handled as a big list of hashes
    '''
    def display(hashstr, word, matches='NA', misses='NA;'):
        # We need to aquire the print lock in case we are multithreaded
        with PRINT_LOCK:
            if args.debug:
                print('{:s} {:s} [matches:{:} misses:{:}]'.format(hashstr, word, matches, misses))
            else:
                print('{:s} {:s}'.format(hashstr, word if word != None else '!!! HASH NOT FOUND !!!'))
        # If the password has not successfully been cracked, we add
        # it to the 'uncrackable' file in the database. This seems
        # like an odd place for this but its common code for threaded
        # and unthreaded versions
        if word is None and uncrackable != None:
            uncrackable(location, hashstr)
    def parseHashes(hashes):
        for item in hashes:
            if os.path.isfile(item):
                with open(item, 'r') as fh:
                    for line in fh:
                        yield line.strip() if ':' not in line else line.split(':')[-1].strip()
            elif item == '-':
                for line in sys.stdin:
                    yield line.strip() if ':' not in line else line.split(':')[-1].strip()
            else:
                yield item if ':' not in item else item.split(':')[-1]
    def worker(queue, complete, available_algorithms):
        while not queue.empty() or not complete.is_set():
            try:
                hashstr, hashbytes = queue.get(True, 1)
            except: continue
            if hashbytes in EMPTYHASH:
                result = (EMPTYHASH[hashbytes], '',) 
            else:
                result = lookup(location, hashbytes, available=available_algorithms)
            algorithm, word = result if result != None else ('', '***UNKNOWN***',)
            display(hashstr, word)


    available_algorithms = getAlgorithms(location)
    if threads in (None, 0, 1,):
        # Single threaded version
        for hashstr in parseHashes(hashes):
            hashbytes = binascii.unhexlify(hashstr)
            if hashbytes in EMPTYHASH:
                result = (EMPTYHASH[hashbytes], '',)
            else:
                result = lookup(location, hashbytes, available_algorithms)
            algorithm, word = result if result != None else ('', '***UNKNOWN***',)
            display(hashstr, word)
    else:
        # Multithreaded version
        queue = multiprocessing.Queue(1000)
        complete = multiprocessing.Event()
        workers = []
        for i in xrange(threads):
            p = multiprocessing.Process(target=worker, args=(queue, complete, available_algorithms))
            p.daemon = True
            p.start()
            workers.append(p)
        try:
            for hashstr in parseHashes(hashes):
                queue.put((hashstr, binascii.unhexlify(hashstr),))
        except KeyboardInterrupt:
            print('\r[+] Interrupted. During crack')
            return
        finally:
            complete.set()
            for i in xrange(threads):
                workers[i].join()

def export(location):
    '''
    Entry point to the export command.
    The purpose of this is to export the wordlists in the database
    to a user readable text file rather than their compressed form
    '''
    for wordsize, index, word in getWords(location):
        print(word)

def importnew(location, wordlists, maxsize=None, ignore=None, wordfilter=None, sortafter=True, count=None, threads=None):
    '''
    Entrypoint to the import command
    The purpose of this is to import new words into the existing database
    By its nature, this needs to take place in two stages. First, we do a
    normal lookup of all the words and build a new wordlist ignoring duplicates
    Then we append the new words to the wordlist and hash files.
    We use a special "appended" table type for special sorting later on
    '''
    # Check that we have no unsorted tables
    if hasUnsortedTables(location):
        print('[!] ERROR: Database has unsorted tables.')
        print('[!]        Run sort before continuing')
        return
    # Build the temporary wordlist path
    newwords_file = os.path.join(location, '_new.txt')
    # Get our list of algorithms already built
    availablealgorithms = getAlgorithms(location)
    args.algorithm = availablealgorithms
    if len(availablealgorithms) == 0:
        print('[!] Cannot import to database with no existing algorithms')
        return False
    # We have a preference for algorithm based on relative speed
    # Check preferred algo list
    checkalgorithm = None
    for algorithm in ('md5', 'sha1', 'sha256', 'sha512',) + tuple(ALGORITHM.keys()):
        if algorithm in availablealgorithms:
            checkalgorithm = algorithm
    print('[+] Importing new words')
    with open(newwords_file, 'wt') as wfh:
        for word in readWordlists(wordlists, maxsize=maxsize, ignore=ignore, wordfilter=wordfilter, count=count):
            hsh = ALGORITHM[checkalgorithm](word)
            # Try the lookup
            if lookup(location, hsh, availablealgorithms) != None:
                continue
            wfh.write(word + '\n')
    print('[+] Delta wordlist built. Importing new words')
    # Mark any existing files as unsorted
    markAlgorithmsAppended(location)
    # Now pass into the normal importwords
    importwords(location, (newwords_file,), maxsize=maxsize, ignore=ignore, wordfilter=wordfilter, count=count, importmode=True, threads=threads)
    # Now delete the temporary import file
    os.unlink(newwords_file)

if __name__ == '__main__':
    def parseAlgorithms(algorithms):
        if algorithms == None:
            algorithms = ['sha1', 'sha256', 'md5', 'ntlm', ]
        elif 'all' in algorithms:
            algorithms = ALGORITHM.keys()[:]
        else:
            algorithms = algorithms.split(',')
        # Validate algorithm list
        invalid = [a for a in algorithms if a not in ALGORITHM.keys()]
        if len( invalid ) > 0:
            print('[!] ERROR: Unknown algorithm(s): {:s}'.format(','.join(invalid)))
            sys.exit(-1)
        return algorithms

    parser = argparse.ArgumentParser(description='Password hash cracking tool',
                                     epilog='For additional help, type an action and --help')
    parser.add_argument('action', choices=('wordlistinfo', 'build', 'sort', 'crack', 'add', 'import', 'export', 'serve',), help='Operation to perform')
    args = parser.parse_args(sys.argv[1:2])

    if args.action == 'wordlistinfo':
        parser = argparse.ArgumentParser(description='Wordlistinfo. Analyse a wordlist')
        parser.add_argument('wordlist', nargs='+', help='Wordlist to analyse')
        parser.add_argument('--filter', help='Regex to filter only these lines. Usually enforcing printable')
        parser.add_argument('--ignore', help='Regex to ignore. Commonly used for easily brute forceable')
        parser.add_argument('--max', type=int, help='Maximum word length')
        args = parser.parse_args(sys.argv[2:])
        wordlistinfo(args.wordlist, args.max, args.ignore, args.filter)
    elif args.action == 'build':
        parser = argparse.ArgumentParser(description='Build. Build a new database with an initial wordlist',
                                         epilog='Note: It is faster to build a database on an SSD due to the sorting')
        parser.add_argument('location', help='Location of the cracking database')
        parser.add_argument('wordlist', nargs='+', help='Wordlist to build database with (use "-" for stdin)')
        parser.add_argument('-a', '--algorithm', type=str, help='Comma separated algorithms to generate')
        parser.add_argument('-c', '--count', type=int, help='Maximum number of words to parse from wordlist')
        parser.add_argument('--max', type=int, help='Maximum word length')
        parser.add_argument('--filter', help='Regex to filter only these lines. Usually enforcing printable')
        parser.add_argument('--ignore', help='Regex to ignore. Commonly used for easily brute forceable')
        parser.add_argument('-t', '--threads', default=multiprocessing.cpu_count(), type=int, help='Number of processing threads to use')
        args = parser.parse_args(sys.argv[2:])
        # Unpack algorithm list
        args.algorithm = parseAlgorithms(args.algorithm)
        importwords(args.location, args.wordlist, args.max, args.ignore, args.filter, count=args.count, threads=args.threads)
    elif args.action == 'sort':
        parser = argparse.ArgumentParser(description='Sort. Sort the database files ready for lookup')
        parser.add_argument('location', help='Location of the cracking database')
        parser.add_argument('-t', '--threads', default=multiprocessing.cpu_count(), type=int, help='Number of processing threads to use')
        parser.add_argument('-c', '--count', type=int, help='Maximum number of files to process')
        args = parser.parse_args(sys.argv[2:])
        sortDatabase(args.location, threads=args.threads, count=args.count)
    elif args.action == 'crack':
        parser = argparse.ArgumentParser(description='Crack. Crack password hashes')
        parser.add_argument('location', help='Location of the cracking database')
        parser.add_argument('hash', nargs='+', help='Cracking target. Could be a hash or a file path')
        parser.add_argument('-t', '--threads', type=int, help='Number of processing threads to use')
        parser.add_argument('-d', '--debug', action='store_true', help='Output debug information')
        parser.add_argument('-a', '--archive', action='store_true', help='Archive uncracked hashes')
        args = parser.parse_args(sys.argv[2:])
        uncrackable = storeUncrackable if args.archive else None
        crack(args.location, args.hash, threads=args.threads, uncrackable=uncrackable)
    elif args.action == 'add':
        parser = argparse.ArgumentParser(description='Add. Add an additional algorithm to the database')
        parser.add_argument('location', help='Location of the cracking database')
        parser.add_argument('-a', '--algorithm', nargs='+', choices=ALGORITHM.keys()+['all', ], help='Comma separated algorithms to generate')
        parser.add_argument('-t', '--threads', default=multiprocessing.cpu_count(), type=int, help='Number of processing threads to use')
        args = parser.parse_args(sys.argv[2:])
        # Unpack algorithm list
        args.algorithm = parseAlgorithms(args.algorithm)
        importwords(args.location, threads=args.threads)
    elif args.action == 'import':
        parser = argparse.ArgumentParser(description='Import. Import new words into the existing tables',
                                         epilog='Note: It is faster to build a database on an SSD due to the sorting')
        parser.add_argument('location', help='Location of the cracking database')
        parser.add_argument('wordlist', nargs='+', help='Wordlist to build database with (use "-" for stdin)')
        parser.add_argument('-c', '--count', type=int, help='Maximum number of words to parse from wordlist')
        parser.add_argument('--max', type=int, help='Maximum word length')
        parser.add_argument('--filter', help='Regex to filter only these lines. Usually enforcing printable')
        parser.add_argument('--ignore', help='Regex to ignore. Commonly used for easily brute forceable')
        parser.add_argument('-t', '--threads', default=multiprocessing.cpu_count(), type=int, help='Number of processing threads to use')
        args = parser.parse_args(sys.argv[2:])
        importnew(args.location, args.wordlist, args.max, args.ignore, args.filter, count=args.count, threads=args.threads)
    elif args.action == 'export':
        parser = argparse.ArgumentParser(description='Export. Export the wordlist entries to screen')
        parser.add_argument('location', help='Location of the cracking database')
        args = parser.parse_args(sys.argv[2:])
        export(args.location)
    elif args.action == 'serve':
        parser = argparse.ArgumentParser(description='Serve. Serve a web interface to the password cracker')
        parser.add_argument('location', help='Location of the cracking database')
        parser.add_argument('-p', '--port', type=int, default=8080, help='Port to listen on')
        parser.add_argument('-a', '--address', default='0.0.0.0', help='Address to listen on')
        args = parser.parse_args(sys.argv[2:])
        webserver.startServer(args.location, address=args.address, port=args.port)
