#!/bin/python
# coding: utf-8

from dataclasses import dataclass, field
from io import StringIO
from typing import Dict, Iterable, List, Optional
import os
import re

from appdirs import user_data_dir
from dataclasses_json import config, DataClassJsonMixin, LetterCase
from pyfzf.pyfzf import FzfPrompt
import plumbum
import requests


@dataclass
class Service(DataClassJsonMixin):
    dataclass_json_config = config(letter_case=LetterCase.PASCAL)['dataclasses_json']

    string_prefix: str
    actions: List[str]
    condition_keys: Optional[List[str]] = None
    has_resource: Optional[bool] = None
    arn_regex: Optional[str] = field(metadata=config(field_name='ARNRegex'), default=None)
    arn_format: Optional[str] = field(metadata=config(field_name='ARNFormat'), default=None)


@dataclass
class Policies(DataClassJsonMixin):
    dataclass_json_config = config(letter_case=LetterCase.CAMEL)['dataclasses_json']

    condition_operators: List[str]
    condition_keys: List[str]
    service_map: Dict[str, Service]


def select_menu(candidates: Iterable[str], prompt: str, multi: bool) -> Optional[List[str]]:
    fzf = FzfPrompt()
    opts = ''
    if multi:
        opts = '--multi'
    result = fzf.prompt(candidates, f'{opts} --cycle --reverse --prompt "{prompt}: "')
    if result == []:
        return None
    return result


# def select_menu(candidates: Iterable[str], prompt: str) -> Optional[str]:
#     tty = os.ttyname(sys.stdout.fileno())
#     percol = subprocess.Popen(
#         ['/bin/percol', '--tty', tty, '--prompt', prompt + ': '],
#         stdin=subprocess.PIPE,
#         stdout=subprocess.PIPE,
#         stderr=subprocess.PIPE
#     )
#     assert percol.stdin is not None
#     assert percol.stdout is not None
#     assert percol.stderr is not None
#     percol.stdin.write('\n'.join(candidates).encode('utf-8'))
#     percol.stdin.close()
#     return percol.stdout.read().decode('utf-8').strip()


def load_policies(url: str, cache: str) -> Policies:
    if os.path.exists(cache):
        with open(cache) as f:
            return Policies.from_json(f.read())
    else:
        response = requests.get(url)
        json_text = response.text.replace('app.PolicyEditorConfig=', '')
        with open(cache, 'w') as f:
            print(json_text, file=f)
        return Policies.from_json(json_text)


def input_service(policies: Policies, insert_end: bool) -> Optional[Service]:
    services = list(map(lambda kv: f'{kv[0]} [{kv[1].string_prefix}]', policies.service_map.items()))
    if insert_end:
        services.insert(0, 'end')
    service_names = select_menu(candidates=services, prompt='Service', multi=False)
    if service_names is None:
        return None
    if insert_end and service_names == ['end']:
        return None
    result = []
    for name in service_names:
        found = policies.service_map.get(re.sub(r'''\s*\[.+\]$''', '', name))
        if found is not None:
            result.append(found)
    if result == []:
        return None
    return result[0]


def input_actions(service: Service) -> Optional[List[str]]:
    actions = select_menu(service.actions, prompt=f'Actions for {service.string_prefix}', multi=True)
    if actions is None:
        return None
    return actions


def embed_variables(fmt: str) -> str:
    def rep(source: str, key: str, value: str) -> str:
        if value is None:
            return source
        source = re.sub(f'<{key}>', value, source, flags=re.IGNORECASE)
        source = re.sub(rf'\$?\{{{key}\}}', value, source, flags=re.IGNORECASE)
        return source

    s = fmt
    s = rep(s, 'region', '${AWS::Region}')
    s = rep(s, 'account[-_]?id', '${AWS::AccountId}')

    if s == fmt:
        return f"""'{s}'"""

    return f"""!Sub '{s}'"""


def write_policy_header(file: StringIO) -> None:
    print('    PolicyDocument:', file=file)
    print('      Version: 2012-10-17', file=file)
    print('      Statement:', file=file)


def write_policy(service: Service, actions: List[str], file: StringIO) -> None:
    print('        - Effect: Allow', file=file)
    if service.arn_format is not None:
        arn = embed_variables(service.arn_format)
    else:
        arn = "'*'"
    print(f"          Resource: {arn}", file=file)
    print('          Action:', file=file)
    for action in actions:
        print(f'            - {service.string_prefix}:{action}', file=file)


def main() -> None:
    url = 'https://awspolicygen.s3.amazonaws.com/js/policies.js'
    data_dir = user_data_dir('aws-policy-generator', 'anekos')
    os.makedirs(data_dir, exist_ok=True)
    cache = os.path.join(data_dir, 'aws-policies.js')

    buffer = StringIO()

    write_policy_header(buffer)

    policies = load_policies(url, cache)
    insert_end = False

    try:
        while True:
            service = input_service(policies, insert_end=insert_end)
            if service is None:
                break

            actions = input_actions(service)
            if actions is None:
                break

            write_policy(service, actions, buffer)
            insert_end = True
    except plumbum.commands.processes.ProcessExecutionError:
        pass

    print(buffer.getvalue())
