"""Actual journal plus mocked Docker failure ordering. No kernel proof."""

import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.lease_journal import LeaseJournal
from scripts.verify_pair_supervisor_contract import instance, engine, run, TOKEN, require


def setup(journal):
    value = instance()
    value.journal = journal
    engine(value)
    original = value._call
    def call(arguments, deadline):
        if arguments[0] == 'info':
            return json.dumps({'OSType': 'linux', 'CgroupVersion': '2', 'ID': 'fixture-engine'})
        return original(arguments, deadline)
    value._call = Mock(side_effect=call)
    return value


def main():
    with tempfile.TemporaryDirectory(prefix='dxr-journal-contract-') as temporary:
        parent = Path(temporary).resolve()
        for case in ('valid', 'capacity', 'intent', 'created', 'removed', 'finish'):
            with LeaseJournal(parent / case) as journal:
                value = setup(journal)
                if case == 'capacity':
                    journal.create = Mock(side_effect=OSError('capacity unavailable'))
                elif case in ('intent', 'created', 'removed'):
                    original = getattr(journal, case)
                    def fail_worker(token, role, *args, original=original, case=case):
                        if role == 'worker':
                            if case == 'intent':
                                original(token, role, *args)  # Crash/failure after intent commit.
                            raise OSError('fixture journal failure')
                        return original(token, role, *args)
                    setattr(journal, case, fail_worker)
                elif case == 'finish':
                    journal.finish = Mock(side_effect=OSError('finish unavailable'))
                result = run(value, parent / (case + '.json'), reject=case != 'valid')
                records = journal.snapshot()
                if case == 'valid':
                    require(result.artifact_eligible and not records, 'valid durable lease did not complete')
                elif case == 'capacity':
                    require(not value._call.called and not records, 'capacity failure contacted engine')
                else:
                    require(len(records) == 1, 'failed durable lease forgotten')
                    resources = records[0]['resources']
                    if case == 'intent':
                        require(resources['worker']['state'] == 'intent' and value._cleanup.call_count == 2,
                                'failed intent led to unjournaled worker creation')
                    if case == 'created':
                        require(resources['worker'] == {'state': 'intent', 'id': None}
                                and resources['volume']['state'] == 'created', 'failed ID commit lost ambiguity')
                    if case == 'removed':
                        require(resources['worker']['state'] == 'created' and resources['volume']['state'] == 'created',
                                'failed removal proof erased authority')
                    if case == 'finish':
                        require(all(r['state'] == 'removed' for r in resources.values()), 'finish failure lost cleanup proof')
                print(case + ': journal/engine ordering verified, no failed artifact')
    print('Verified actual-journal fault injection against mocked Docker. Automatic recovery remains pending.')


if __name__ == '__main__':
    main()
