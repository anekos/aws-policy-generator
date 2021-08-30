#!/bin/python
# coding: utf-8

from dataclasses import dataclass, field
from io import StringIO
from typing import Callable, Dict, Iterable, List, Optional
import os
import re
import sys

from appdirs import user_data_dir
from dataclasses_json import config, DataClassJsonMixin, LetterCase
from pyfzf.pyfzf import FzfPrompt
import boto3
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


def select_menu(candidates: Iterable[str], prompt: str) -> Optional[List[str]]:
    fzf = FzfPrompt()
    result = fzf.prompt(candidates, f'--multi --cycle --reverse --prompt "{prompt}: "')
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


def input_services(policies: Policies) -> Optional[List[Service]]:
    services = map(lambda kv: f'{kv[0]} [{kv[1].string_prefix}]', policies.service_map.items())
    service_names = select_menu(candidates=services, prompt='Service')
    if service_names is None:
        return None
    result = []
    for name in service_names:
        found = policies.service_map.get(re.sub(r'''\s*\[.+\]$''', '', name))
        if found is not None:
            result.append(found)
    if result == []:
        return None
    return result


def input_actions(service: Service) -> Optional[List[str]]:
    actions = select_menu(service.actions, prompt=f'Actions for {service.string_prefix}')
    if actions is None:
        return None
    return actions


def variables_embeder(region: Optional[str], account_id: Optional[str]) -> Callable[[str], str]:
    def embed_variables(fmt: str) -> str:
        if region is not None:
            fmt = fmt.replace('<region>', region)
            fmt = fmt.replace('${Region}', region)
        if account_id is not None:
            fmt = fmt.replace('<account>', account_id)
            fmt = fmt.replace('${account}', account_id)
        return fmt
    return embed_variables


def write_policy_header(file: StringIO) -> None:
    print('    PolicyDocument:', file=file)
    print('      Version: 2012-10-17', file=file)
    print('      Statement:', file=file)


def policy_writer(embeder: Callable[[str], str]) -> Callable[[Service, List[str], StringIO], None]:
    def write_policy(service: Service, actions: List[str], file: StringIO) -> None:
        print('        - Effect: Allow', file=file)
        if service.arn_format is not None:
            arn = embeder(service.arn_format)
        else:
            arn = '*'
        print(f"          Resource: '{arn}'", file=file)
        print('          Action:', file=file)
        for action in actions:
            print(f'            - {service.string_prefix}:{action}', file=file)
    return write_policy


def main() -> None:
    url = 'https://awspolicygen.s3.amazonaws.com/js/policies.js'
    data_dir = user_data_dir('aws-policy-generator', 'anekos')
    os.makedirs(data_dir, exist_ok=True)
    cache = os.path.join(data_dir, 'aws-policies.js')

    region: Optional[str] = os.environ.get('AWS_DEFAULT_REGION') or os.environ.get('AWS_REGION')

    account_id: Optional[str]
    try:
        sts_client = boto3.client('sts')
        account_id = sts_client.get_caller_identity()['Account']
    except Exception:
        account_id = None

    embeder = variables_embeder(region, account_id)
    write_policy = policy_writer(embeder)

    buffer = StringIO()

    write_policy_header(buffer)

    policies = load_policies(url, cache)

    services = input_services(policies)
    if services is None:
        return None

    for service in services:
        actions = input_actions(service)
        if actions is None:
            return None

        write_policy(service, actions, buffer)

    print(buffer.getvalue())


def wrapped_main() -> None:
    import plumbum

    try:
        main()
    except plumbum.commands.processes.ProcessExecutionError:
        sys.exit(1)


if __name__ == '__main__':
    import fire
    fire.Fire(wrapped_main)
