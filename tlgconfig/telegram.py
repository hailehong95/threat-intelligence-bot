import os

TLG_BOT_TOKEN = os.getenv('TLG_BOT_TOKEN')


class TelegramConfig:
    def __init__(self, api_key=None, chat_id=None, username=None, is_private=False, is_enable=False):
        self.__api_key = api_key
        self.__chat_id = chat_id
        self.__username = username
        self.__is_private = is_private
        self.__is_enable = is_enable

    @property
    def api_key(self):
        return self.__api_key

    @api_key.setter
    def api_key(self, api_key):
        self.__api_key = api_key

    @property
    def chat_id(self):
        return self.__chat_id

    @chat_id.setter
    def chat_id(self, chat_id):
        self.__chat_id = chat_id

    @property
    def username(self):
        return self.__username

    @username.setter
    def username(self, username):
        self.__username = username

    @property
    def is_private(self):
        return self.__is_private

    @is_private.setter
    def is_private(self, is_private):
        self.__is_private = is_private

    @property
    def is_enable(self):
        return self.__is_enable

    @is_enable.setter
    def is_enable(self, is_enable):
        self.__is_enable = is_enable

    def dump_config(self):
        tlg_config = {'api_key': self.__api_key, 'chat_id': self.__chat_id, 'username': self.__username,
                      'is_private': self.__is_private, 'is_enable': self.__is_enable}
        return tlg_config
