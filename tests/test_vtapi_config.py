#!/usr/bin/env python

import os
import json

TEST_DIR = os.path.dirname(os.path.realpath(__file__))
JSON_FILE = os.path.join(TEST_DIR, 'config.json')


def user_input():
    name = str(input('Enter your name: '))
    user_id = str(input('Enter your id: '))
    key = str(input('Enter your key: '))
    return {'author': name, 'user_id': user_id, 'api_key': key}


def read_config(file_path):
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f_in:
                json_data = json.load(f_in)
            return json_data
    except Exception as err:
        print(err)


def write_config(file_path, json_data):
    try:
        with open(file_path, 'w') as f_out:
            json.dump(json_data, f_out, sort_keys=False, indent=4)
    except Exception as err:
        print(err)


def init_config():
    json_data = []
    item = user_input()
    json_data.append(item)
    write_config(JSON_FILE, json_data)


def save_config():
    json_data = read_config(JSON_FILE)
    api_keys = [key.get('api_key') for key in json_data]
    item = user_input()
    if item.get('api_key') not in api_keys:
        json_data.append(item)
    else:
        print('API Key is available!')
    write_config(JSON_FILE, json_data)


def vt_load_config():
    if os.path.exists(JSON_FILE):
        save_config()
    else:
        init_config()


if __name__ == '__main__':
    vt_load_config()
