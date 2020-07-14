import subprocess
import hashlib
from typing import Any, List, Tuple, Dict, Optional
import pickle
import os
import time
import itertools
from pathlib import Path
from semgrep.util import default_dict_dict_of_list, print_time

MD5_CACHE_DIR = "/tmp/semgrep-cache/"


def grouper(n, iterable):
    it = iter(iterable)
    while True:
       chunk = tuple(itertools.islice(it, n))
       if not chunk:
           return
       yield chunk

class ContentHashStore(object):
    # in-memory cache backed by filesystem
    # only writes to filesystem if we call flush() to make it more multi-process-safe

    cache_name = "cache.pickle"
    cache_dir: Path = MD5_CACHE_DIR
    cache_path: Path = os.path.join(cache_dir, cache_name)

    # by pattern hash, then file content hash
    semgrep_md5_hash: Dict[str, Dict[str, List[Any]]] = default_dict_dict_of_list()

    def contains(self, file_hash: str, patterns_hash: str) -> bool:
        return file_hash in self.semgrep_md5_hash[patterns_hash]

    def _get(self, file_hash, patterns_hash) -> Optional[Any]:
        if self.contains(file_hash, patterns_hash):
            return self.semgrep_md5_hash[patterns_hash][file_hash]
        return None

    def save_entry(self, file_hash: str, patterns_hash: str, contents: Any):
        self.semgrep_md5_hash[patterns_hash][file_hash] = contents

    def load_entry(self, file_hash: str, patterns_hash: str):
        return self._get(file_hash, patterns_hash)        

    def load(self):
        start_t = time.time()
        self.semgrep_md5_hash = pickle.load(open(self.cache_path, 'rb'))
        print(f'loaded {len(self.semgrep_md5_hash)} cache entries...in {print_time(start_t)}s')

    def flush(self):
        # save everything in the cache which isn't yet persisted to disk
        # get a lock on the file        
        start_t = time.time()
        with open(self.cache_path, 'wb') as fout:
            pickle.dump(self.semgrep_md5_hash, fout)
        print(f'wrote {len(self.semgrep_md5_hash)} cache entries...in {print_time(start_t)}s')

    @classmethod
    def git_hash(cls, fname: Path) -> str:
        """Try to get the git hash. Fallback for files that are not in git."""
        args = ["/usr/bin/git", "rev-parse", f"HEAD:{fname}"]
        try:
            h = subprocess.check_output(args).decode('utf-8')
            h = h.strip()
            assert len(h) == 41 or len(h) == 40, f'{h} should be 41 len'
            return h
        except subprocess.CalledProcessError as ex:
            if "exists on disk, but not in 'HEAD'" in ex.message:
                return md5_hash(fname)
            else:
                raise ex


    @classmethod
    def git_hashes(cls, fnames: List[Path]) -> List[Tuple[str, str]]:
        """Try to get the git hash. Fallback for files that are not in git."""
        # group filenames in blocks of size ARGMAX (rough approximation)
        for fnames_block in grouper(128*64, fnames):
            print(len(fnames_block))
            args = ["/usr/bin/git", "rev-parse"] + [f'HEAD:{fname}' for fname in fnames_block]
            try:
                h = subprocess.check_output(args).decode('utf-8')
                h = h.strip()
                hashes = h.split('\n')
                yield from zip(fnames_block, hashes)
                #assert len(h) == 41 or len(h) == 40, f'{h} should be 41 len'
            except subprocess.CalledProcessError as ex:
                if "exists on disk, but not in 'HEAD'" in str(ex):
                    # fallback to md5
                    for fname in fnames_block:
                        yield fname, md5_hash(fname)
                else:
                    raise ex


    @classmethod
    def md5_hash(cls, fname: Path) -> str:
        hash_md5 = hashlib.md5()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
