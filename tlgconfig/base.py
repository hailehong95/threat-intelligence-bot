import os


class BaseConfig:
    def __init__(self):
        self.__config_dir = os.path.dirname(os.path.realpath(__file__))
        self.__base_dir = os.path.dirname(self.__config_dir)
        self.__data_dir = os.path.join(self.__base_dir, 'data')
        self.__user_db_dir = os.path.join(self.__base_dir, 'user_db')

    @property
    def base_dir(self):
        return self.__base_dir

    @property
    def user_db_dir(self):
        return self.__user_db_dir

    @property
    def data_dir(self):
        return self.__data_dir
