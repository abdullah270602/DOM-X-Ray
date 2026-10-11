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
        for case in ('valid', 'capacity', 'intent', 'intent-initialize', 'intent-broker', 'intent-volume',
                     'created', 'removed', 'finish'):
            with LeaseJournal(parent / case) as journal:
                value = setup(journal)
                if case == 'capacity':
                    journal.create = Mock(side_effect=OSError('capacity unavailable'))
                elif case in ('intent', 'created', 'removed') or case.startswith('intent-'):
                    method = 'intent' if case.startswith('intent') else case
                    fault_role = case.removeprefix('intent-') if case.startswith('intent-') else 'worker'
                    if method == 'intent' and fault_role != 'volume':
                        value._remove_volume = Mock(side_effect=AssertionError('volume removed after ambiguous intent'))
                    if fault_role == 'volume':
                        original_call = value._call
                        value._call = Mock(side_effect=lambda arguments, deadline: (
                            '' if arguments[:2] == ['volume', 'ls'] else original_call(arguments, deadline)))
                    original = getattr(journal, method)
                    def fail_worker(token, role, *args, original=original, method=method, fault_role=fault_role):
                        if role == fault_role:
                            if method == 'intent':
                                original(token, role, *args)  # Crash/failure after intent commit.
                            raise OSError('fixture journal failure')
                        return original(token, role, *args)
                    setattr(journal, method, fail_worker)
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
                        require(resources['worker']['state'] == 'intent' and value._cleanup.call_count == 3
                                and not value._remove_volume.called and resources['volume']['state'] == 'created',
                                'ambiguous intent skipped role/removed volume or lost authority')
                    if case in ('intent-initialize', 'intent-broker'):
                        require(resources[fault_role]['state'] == 'intent'
                                and value._cleanup.call_count == (1 if fault_role == 'initialize' else 2)
                                and not value._remove_volume.called and resources['volume']['state'] == 'created',
                                'ambiguous early role intent skipped cleanup/removed shared volume')
                    if case == 'intent-volume':
                        require(resources['volume']['state'] == 'intent' and value._cleanup.call_count == 0
                                and any(call.args[0][:2] == ['volume', 'ls'] for call in value._call.call_args_list)
                                and not any(call.args[0][:2] == ['volume', 'rm'] for call in value._call.call_args_list),
                                'ambiguous volume intent skipped lookup or removed an unowned volume')
                    if case == 'created':
                        require(resources['worker'] == {'state': 'intent', 'id': None}
                                and resources['volume']['state'] == 'created', 'failed ID commit lost ambiguity')
                    if case == 'removed':
                        require(resources['worker']['state'] == 'created' and resources['volume']['state'] == 'created',
                                'failed removal proof erased authority')
                    if case == 'finish':
                        require(all(r['state'] == 'removed' for r in resources.values()), 'finish failure lost cleanup proof')
                print(case + ': journal/engine ordering verified, no failed artifact')
    print('Verified actual-journal fault injection against mocked Docker. Automatic watchdog deployment remains pending.')


if __name__ == '__main__':
    main()
