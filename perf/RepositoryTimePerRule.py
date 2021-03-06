from collections import defaultdict
from typing import Dict, List
from operator import add

import copy
import json
import sys

class TotalTimeAndTargetNum:
    def __init__(self, total_rule_time: float = 0.0, num_targets: int = 0):
        self.total_rule_time = total_rule_time
        self.num_targets = num_targets

    def __add__(self, other):
        added_total_rule_time = self.total_rule_time + other.total_rule_time
        added_num_targets = self.num_targets + other.num_targets
        return TotalTimeAndTargetNum(added_total_rule_time, added_num_targets)

    def return_average(self):
        return self.total_rule_time/self.num_targets

class RepositoryTimePerRule:
    def __init__(
        self,
        output_file: str,
        repo_to_times_per_rule: Dict[str, Dict[str, float]] = defaultdict(dict),
        rules_to_total_time_num_files: Dict[str, TotalTimeAndTargetNum] = defaultdict(TotalTimeAndTargetNum)
    ) -> None:
        self.repo_to_times_per_rule = repo_to_times_per_rule
        self.output_file = output_file
        self.rules_to_total_time_num_files = rules_to_total_time_num_files

    def _calculate_time_per_rule(self) -> Dict[str, float]:
        time_per_rule_dict = defaultdict(float)
        for rule_id, total_time_target_num in self.rules_to_total_time_num_files.items():
            time_per_rule_dict[rule_id] = total_time_target_num.return_average()
        return dict(sorted(time_per_rule_dict.items(), key=lambda item: -item[1]))

    def times_per_file_to_times_per_rule(self, repo_name: str, times_per_file_bytes: bytes):
        try:
            times_per_file = json.loads(times_per_file_bytes.decode('utf-8'))
        except (UnicodeDecodeError, ValueError):
            print ("Unable to decode the Semgrep result as JSON.")
            sys.exit(1)

        if not 'time' in times_per_file:
            print ("Semgrep-core ran without the --time flag, please try again with --time set to true.")
            sys.exit(1)

        rule_ids = []
        for rule_id in times_per_file['time']['rules']:
            rule_ids.append(rule_id['id'])

        # this is for repo -> rule_id -> time
        total_time_per_rule: List[str] = [0] * len(rule_ids)
        # this is for rule_id -> average file time, want to remove all 0 run-times
        repo_time_per_rule_no_zeroes: Dict[str, TotalTimeAndTargetNum] = defaultdict(TotalTimeAndTargetNum)
        for target in times_per_file['time']['targets']:
            total_time_per_rule = list(map(add, target['parse_times'], total_time_per_rule))
            for idx, parse_time in enumerate(target['parse_times']):
                if parse_time > 0:
                    repo_time_per_rule_no_zeroes[rule_ids[idx]] = repo_time_per_rule_no_zeroes[rule_ids[idx]] + TotalTimeAndTargetNum(parse_time, 1)
        current_repo_times = dict(zip(rule_ids, total_time_per_rule))
        self.repo_to_times_per_rule[repo_name] = dict(sorted(current_repo_times.items(), key=lambda item: -item[1]))

        # add to the overall per-rule statistics
        for rule_id, total_time_per_rule in repo_time_per_rule_no_zeroes.items():
                changed_results = self.rules_to_total_time_num_files[rule_id] + total_time_per_rule
                self.rules_to_total_time_num_files[rule_id] = changed_results

    def print_repo_to_times_per_rule(self):
        time_per_rule = self._calculate_time_per_rule()
        output = {
            'repository_to_times_per_rule': self.repo_to_times_per_rule,
            'time_per_rule_average': time_per_rule
        }
        with open(self.output_file, 'w') as f:
            json.dump(output, f)
