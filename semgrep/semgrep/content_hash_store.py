import subprocess
import hashlib
from typing import Any, List, Tuple, Dict, Optional
import pickle
import os
from pathlib import Path
from semgrep.util import default_dict_dict_of_list

MD5_CACHE_DIR = "/tmp/semgrep-cache/"

class ContentHashStore(object):
    # in-memory cache backed by filesystem
    # only writes to filesystem if we call flush() to make it more multi-process-safe

    cache_dir: Path = MD5_CACHE_DIR

    # by pattern hash, then file content hash
    semgrep_md5_hash: Dict[str, Dict[str, List[Any]]] = default_dict_dict_of_list()
    dirty: List[Tuple[str, str]] = []

    def contains(self, file_hash: str, patterns_hash: str) -> bool:
        return file_hash in self.semgrep_md5_hash[patterns_hash]

    def _get(self, file_hash, patterns_hash) -> Optional[Any]:
        if self.contains(file_hash, patterns_hash):
            return self.semgrep_md5_hash[patterns_hash][file_hash]
        return None

    def save_entry(self, file_hash: str, patterns_hash: str, contents: Any):
        self.semgrep_md5_hash[patterns_hash][file_hash] = contents
        self.dirty.append((patterns_hash, file_hash))

    def load_entry(self, file_hash: str, patterns_hash: str):
        # try in-memory cache, then fall back to disk
        in_memory = self._get(file_hash, patterns_hash)
        if in_memory:
            print('hit cache')
            return in_memory

        cache_file_path = os.path.join(self.cache_dir, patterns_hash, file_hash)
        if os.path.exists(cache_file_path):
            print('hit slow')
            self.semgrep_md5_hash[patterns_hash][file_hash] = pickle.load(open(cache_file_path, 'rb'))
        
        return self._get(file_hash, patterns_hash)        

    def flush(self):
        # save everything in the cache which isn't yet persisted to disk
        print(f'writing {len(self.dirty)} cache entries...')
        for (patterns_hash, file_hash) in self.dirty:
            cache_file_path = os.path.join(self.cache_dir, patterns_hash, file_hash)            
            Path(os.path.join(self.cache_dir, patterns_hash)).mkdir(parents=True, exist_ok=True)

            with open(cache_file_path, 'wb') as fout:
                pickle.dump(self.semgrep_md5_hash[file_hash][patterns_hash], fout)
        self.dirty = []

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
    def md5_hash(cls, fname: Path) -> str:
        hash_md5 = hashlib.md5()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
