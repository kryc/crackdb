import os
import mmap
import time
import multiprocessing
import psutil

def strcmp(word1, word2):
    n = min(len(word1), len(word2))
    # Compare the bytes in each word
    for i in xrange(n):
        o1 = word1[i]
        o2 = word2[i]
        if o1 == o2:
            continue
        return o1 - o2
    # Drop down to comparing the lengths
    if len(word1) == len(word2):
        return 0
    elif len(word1) > len(word2):
        return 1
    return -1

def memcmp(word1, word2):
    # Compare the bytes in each word
    for c1, c2 in zip(word1, word2):
        o1 = c1 if isinstance(c1, int) else ord(c1)
        o2 = c2 if isinstance(c2, int) else ord(c2)
        if o1 == o2:
            continue
        return o1 - o2
    return 0

def sortFileBubble(mm, records, width, comparefn, threads=None):
    '''
    Single threaded implementation of the bubble sort algorithm.
    This particular version is optimised to sort files that are already
    sorted but have appended records.
    '''
    changed = True
    while True:
        if changed is False:
            break
        changed = False
        for i in xrange(0, records-1):
            entry1 = mm[i*width : i*width+width]
            entry2 = mm[(i+1)*width : (i+1)*width+width]
            comparison = comparefn(entry1, entry2)
            while comparison > 0:
                writedone = False
                try:
                    mm[i*width : (i+2)*width] = entry2 + entry1
                    writedone = True
                finally:
                    if not writedone:
                        mm[i*width : (i+2)*width] = entry2 + entry1
                changed = True
                # Bubble the change up. By continuing the change up
                # we improve our cache efficiency
                if i == 0:
                    break
                i -= 1
                entry1 = mm[i*width : i*width+width]
                entry2 = mm[(i+1)*width : (i+1)*width+width]
                comparison = comparefn(entry1, entry2)
    return True

def sortFileQuicksort(mm, records, width, comparefn, threads=None):
    '''
    A multithreaded quicksort implementation where partitions are
    pushed onto a worker queue. When called with single threaded, it
    uses a list for efficiency.
    '''
    def partition(mm, begin, end):
        pivot = begin
        for i in xrange(begin+1, end+1):
            entry1 = mm[i*width : i*width+width]
            entry2 = mm[begin*width: begin*width+width]
            comparison = comparefn(entry1, entry2)
            if comparison <= 0:
                pivot += 1
                # Swap mm[pivot] <=> mm[i]
                entryp = mm[pivot*width: pivot*width+width]
                # This code duplication is awful but necessary
                # to prevent corrupting the file if we stop it
                # during the two writes
                writedone = False
                try:
                    mm[pivot*width : pivot*width+width] = entry1
                    mm[i*width : i*width+width] = entryp
                    writedone = True
                finally:
                    if not writedone:
                        mm[pivot*width : pivot*width+width] = entry1
                        mm[i*width : i*width+width] = entryp
        # Swap mm[pivot] <=> mm[begin]
        entryp = mm[pivot*width: pivot*width+width]
        entryb = mm[begin*width : begin*width+width]

        # Same as above, we need to make sure BOTH writes
        # happen to avoid corrupting the file
        writedone = False
        try:
            mm[begin*width : begin*width+width] = entryp
            mm[pivot*width : pivot*width+width] = entryb
            writedone = True
        finally:
            if not writedone:
                mm[begin*width : begin*width+width] = entryp
                mm[pivot*width : pivot*width+width] = entryb
        return pivot
    def worker(uid, queue, complete, working):
        # print('[+] Worker {:} running'.format(uid))
        while not complete.is_set():
            try:
                job = queue.get(True, 1)
                working.set()
            except:
                working.clear()
                continue
            if job is None:
                continue
            begin, end = job
            pivot = partition(mm, begin, end)
            if pivot-1 > begin:
                queue.put((begin, pivot-1,))
            if pivot+1 < end:
                queue.put((pivot+1, end,))

    # Linear implementation
    if threads in (0, 1, None,):
        temp_stack = [(0, records-1,),]
        while temp_stack:
            begin, end = temp_stack.pop()
            pivot = partition(mm, begin, end)
            if pivot-1 > begin:
                temp_stack.append((begin, pivot-1,))
            if pivot+1 < end:
                temp_stack.append((pivot+1, end,))
    # Threaded implementation
    else:
        workers = []
        queue = multiprocessing.Queue()
        working = [multiprocessing.Event() for i in xrange(threads)]
        complete = multiprocessing.Event()
        queue.put((0, records-1,))
        for i in xrange(threads):
            p = multiprocessing.Process(target=worker, args=(i, queue, complete, working[i]))
            p.daemon = True
            p.start()
            workers.append(p)
        while not complete.is_set():
            time.sleep(3)
            processing = False
            for i in xrange(threads):
                if working[i].is_set():
                    processing = True
            if not processing:
                complete.set()
        for i in xrange(threads):
            workers[i].join()
    return True

SORTALGORITHM = {'bubble':sortFileBubble, 'quick':sortFileQuicksort}

def sortFile(handle, width, comparefn, threads=None, algorithm=None, rename=None, forcemmap=False):
    '''
    There are several options when sorting a file, each
    of them depend on the technique that we want to employ.
    If the file is small enough, we will load the entire table into
    memory and sort it there. If it is too large, we will have no
    option but to mmap it.
    This function takes either a file handle or a path as the indication
    as to the file that needs sorting. If it is a handle, we ONLY do memory
    mapped sorting
    '''
    # Get the amount of available system memory
    mem = psutil.virtual_memory()
    mm = None
    closeafter = False

    # If the input type is a string
    if isinstance(handle, str):
        if not os.path.isfile(handle):
            raise OSError('File {:s} not found'.format(handle))
        # We need the number of records no matter how we do the sorting
        filesize = os.path.getsize(handle)
        if filesize % width != 0:
            print('[!] ERROR: Corrupted table. Size does not match record width')
            return False
        # Only one record so return early
        if filesize == width:
            return True
        records = filesize / width
        # We will be quite aggresive and use 75% of available memory.
        # We need to be careful that we dont push the system to page us out
        # in which case using a memory mapped file would be better suited
        if os.path.getsize(handle) < (mem.available * 0.75) and not forcemmap:
            mm = mmap.mmap(-1, filesize)
            with open(handle, 'rb') as fh:
                mm.write(fh.read())
                mm.seek(0, os.SEEK_SET)
            print('[+] In-memory sorting {:s} ({:d} records) using {:d} threads'.format(os.path.basename(handle), records, threads if threads != None else 1))
            algofn = sortFileQuicksort if algorithm is None else SORTALGORITHM[algorithm]
            res = algofn(mm, records, width, comparefn, threads=threads)
            # Return without committing changes if we failed
            if not res:
                print('[!] Sorting failed')
                return False
            # Write the sorted data back to the file
            destfile = rename if rename != None else handle
            with open(destfile, 'wb') as fh:
                fh.write(mm)
            mm.close()
            if rename != None:
                os.unlink(handle)
            return True
        else:
            handle = open(handle, 'r+b')
            closeafter = True
    # Note that we dont use elif as we may drop through to this
    # if we dont have enough memory to load the table into
    if isinstance(handle, file):
        # Get the number of records
        handle.seek(0, os.SEEK_END)
        file_end = handle.tell()
        if file_end % width != 0:
            print('[!] ERROR: Corrupted table. Size does not match record width')
            return False
        records = file_end / width
        # Memory map the file
        handle.seek(0)
        mm = mmap.mmap(handle.fileno(), 0)
        print('[+] Sorting memory-mapped {:s} ({:d} records) using {:d} threads'.format(os.path.basename(handle.name), records, threads if threads != None else 1))
        algofn = sortFileQuicksort if algorithm is None else SORTALGORITHM[algorithm]
        res = algofn(mm, records, width, comparefn, threads=threads)
        mm.flush()
        mm.close()
        if closeafter:
            handle.close()
        # Return without renaming if something went wrong
        if not res:
            return res
        if rename != None:
            os.rename(handle.name, rename)
    return True

def binarySearch(handle, value, width=None, mm=None, entries=None):
    '''
    Generic binary search function for dealing with large binary files
    It is able to quickly search a sorted binary file for a given value
    '''
    def _search(mm, left, right, value, width=None):
        if width is None:
            width = len(value)
        if right >= left:
            mid = left + (right-left)/2
            n = mm[mid*width:mid*width+width]
            h = n[:len(value)]
            comparison = memcmp(h, value)
            if comparison == 0:
                assert(len(h) == len(value))
                results = [n,]
                # Found the first result, new seek each side to find other matches
                for i in xrange(mid-1, -1, -1):
                    n = mm[i*width:i*width+width]
                    h = n[:len(value)]
                    assert(len(h) == len(value))
                    if h == value:
                        results.append(n)
                    else:
                        break
                for i in xrange(mid+1, entries):
                    n = mm[i*width:i*width+width]
                    h = n[:len(value)]
                    assert(len(h) == len(value))
                    if h == value:
                        results.append(n)
                    else:
                        break
                return results
            elif comparison < 0:
                return _search(mm, mid+1, right, value, width)
            else:
                return _search(mm, left, mid-1, value, width)
        else:
            return []
    opened = False
    if mm is None:
        try:
            mm = mmap.mmap(handle.fileno(), 0)
        except ValueError:
            return []
        opened = True
    if entries is None:
        handle.seek(0, os.SEEK_END)
        entries = handle.tell() / (width if width != None else len(value))
        handle.seek(0)
    result = _search(mm, 0, entries-1, value, width)
    if opened:
        mm.close()
    return result
