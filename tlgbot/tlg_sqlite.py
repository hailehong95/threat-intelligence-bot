import os
import sqlite3

from datetime import datetime
from tlglogging.config import logger
from tlgbot.tlg_utils import datetime_to_unix
from tlgconfig import BaseConfig

base_conf = BaseConfig()

DB_PATH = os.path.join(base_conf.data_dir, 'CTI_Bot.db')
TBL_VT_USER = 'VTUsers'
TBL_SD_USER = 'SDUsers'
TBL_VIP_MEMBER = 'VipMember'
TBL_VIP_MEMBER_LOGS = 'VipMemberLogs'
TBL_HUNTING = 'VTHunting'
TBL_HUNTING_LOGS = 'VTHuntingLogs'


# Ref: https://docs.python.org/3.8/library/sqlite3.html#sqlite3.Connection.row_factory
def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


# Create VTHuntingLogs Table
def vt_hunting_logs_create_table(cur):
    try:
        sql_create = """
            CREATE TABLE IF NOT EXISTS {} (
                id               INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
                hunt_id          INT     UNIQUE NOT NULL,
                hunt_chat_id     TEXT,
                hunt_username    TEXT,
                hunt_content     TEXT,
                hunt_last_update INT     DEFAULT (0)
            );
        """.format(TBL_HUNTING_LOGS)
        cur.execute(sql_create)
    except sqlite3.Error as ex:
        logger.warning(str(ex))


# Create VTHunting Table
def vt_hunting_create_table(cur):
    try:
        sql_create = """
            CREATE TABLE IF NOT EXISTS {} (
                id               INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
                hunt_id          INT     NOT NULL UNIQUE,
                hunt_type        TEXT,
                hunt_status      BOOLEAN NOT NULL DEFAULT (0),
                hunt_create_time INT     NOT NULL,
                hunt_chat_id     TEXT,
                hunt_username    TEXT,
                hunt_run_at      TEXT,
                hunt_content     TEXT,
                hunt_checksum    TEXT    NOT NULL,
                hunt_source      TEXT,
                hunt_last_run    INT     DEFAULT (0)
            );
        """.format(TBL_HUNTING)
        cur.execute(sql_create)
    except sqlite3.Error as ex:
        logger.warning(str(ex))


# Create VipMemberLogs Table
def vip_member_logs_create_table(cur):
    try:
        sql_create = """
            CREATE TABLE IF NOT EXISTS {} (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
                create_time        INT     NOT NULL,
                member_chat_id     TEXT    NOT NULL,
                member_username    TEXT    NOT NULL,
                member_key         TEXT    NOT NULL,
                admin_chat_id      TEXT    NOT NULL,
                member_logs_status BOOLEAN NOT NULL DEFAULT (0),
                member_logs        TEXT    NOT NULL
            );
        """.format(TBL_VIP_MEMBER_LOGS)
        cur.execute(sql_create)
    except sqlite3.Error as ex:
        logger.warning(str(ex))


# Create VipMember Table
def vip_member_create_table(cur):
    try:
        sql_create = """
            CREATE TABLE IF NOT EXISTS {} (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
                member_key           TEXT    NOT NULL,
                member_chat_id       TEXT    NOT NULL,
                member_username      TEXT    NOT NULL,
                member_is_private    BOOLEAN NOT NULL DEFAULT (0),
                member_start_time    INT,
                member_end_time      INT,
                member_query_used    INT     DEFAULT (0),
                member_query_allowed INT     DEFAULT (0),
                member_is_query      BOOLEAN DEFAULT (1) NOT NULL,
                admin_key            TEXT    NOT NULL,
                admin_username       TEXT    NOT NULL,
                admin_chat_id        TEXT    NOT NULL
            );
        """.format(TBL_VIP_MEMBER)
        cur.execute(sql_create)
    except sqlite3.Error as ex:
        logger.warning(str(ex))


# Create SDUsers Table
def sd_users_create_table(cur):
    try:
        sql_create = """
            CREATE TABLE IF NOT EXISTS {} (
                id         INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
                shodan_key TEXT    NOT NULL,
                chat_id    TEXT    NOT NULL,
                username   TEXT    NOT NULL
            );
        """.format(TBL_SD_USER)
        cur.execute(sql_create)
    except sqlite3.Error as ex:
        logger.warning(str(ex))


# Create VTUsers Table
def vt_users_create_table(cur):
    """
    Create Sqlite table if not exist
    """
    try:
        sql_create = """
            CREATE TABLE IF NOT EXISTS {} (
                id         INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
                api_key    TEXT    NOT NULL,
                chat_id    TEXT    NOT NULL,
                username   TEXT    NOT NULL,
                is_private BOOLEAN DEFAULT (0) NOT NULL,
                is_enable  BOOLEAN DEFAULT (0) NOT NULL
            );
        """.format(TBL_VT_USER)
        cur.execute(sql_create)
    except sqlite3.Error as ex:
        logger.warning(str(ex))


def db_init(db, to_dict=False):
    """
    Init connection to Sqlite db
    :param db: database path file
    :param to_dict: if equal True, result convert to dict
    :return: object connection
    """
    try:
        con = sqlite3.connect(db, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        if to_dict:
            con.row_factory = dict_factory
            cur = con.cursor()
        else:
            cur = con.cursor()
        vt_users_create_table(cur)
        sd_users_create_table(cur)
        vip_member_create_table(cur)
        vip_member_logs_create_table(cur)
        vt_hunting_create_table(cur)
        vt_hunting_logs_create_table(cur)
    except sqlite3.Error as ex:
        con, cur = None, None
        logger.warning(str(ex))
    return con, cur


def vt_hunting_add_job(job: dict):
    """ ADD new Hunting Job from User """
    try:
        con, cur = db_init(DB_PATH)
        item = (job['hunt_id'], job['hunt_type'], job['hunt_create_time'], job['hunt_chat_id'], job['hunt_username'],
                job['hunt_run_at'], job['hunt_content'], job['hunt_checksum'], job['hunt_source'])
        sql = """
            INSERT INTO {} (hunt_id, hunt_type, hunt_create_time, hunt_chat_id, hunt_username, hunt_run_at, hunt_content, hunt_checksum, hunt_source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """.format(TBL_HUNTING)
        cur.execute(sql, item)
        con.commit()
    except Exception as ex:
        logger.warning(str(ex))
        return False
    finally:
        cur.close()
        con.close()
    return True


def vt_hunting_del_job(hunt_chat_id, hunt_id):
    """ DELETE a Hunting Job by User """
    try:
        con, cur = db_init(DB_PATH)
        sql = """DELETE FROM {} WHERE hunt_chat_id=? AND hunt_id=?""".format(TBL_HUNTING)
        cur.execute(sql, (hunt_chat_id, hunt_id,))
        con.commit()
    except Exception as ex:
        logger.warning(str(ex))
        return False
    finally:
        cur.close()
        con.close()
    return True


def vt_hunting_update_job(hunt_chat_id, hunt_id, hunt_content='', hunt_checksum=''):
    """ UPDATE a Hunting Job by User """
    try:
        con, cur = db_init(DB_PATH)
        if hunt_content and hunt_checksum:
            sql = """UPDATE {}
                     SET hunt_content=?, hunt_checksum=?
                     WHERE hunt_chat_id=? AND hunt_id=?""".format(TBL_HUNTING)
        cur.execute(sql, (hunt_content, hunt_checksum, hunt_chat_id, hunt_id,))
        con.commit()
    except Exception as ex:
        logger.warning(str(ex))
        return False
    finally:
        cur.close()
        con.close()
    return True


def vt_hunting_set_time_job(hunt_chat_id, hunt_id, hunt_status=True, hunt_run_at=''):
    """ SET ON Hunting Job status and schedule times """
    try:
        con, cur = db_init(DB_PATH)
        sql = """ UPDATE {} SET hunt_status=?,hunt_run_at=? WHERE hunt_chat_id=? AND hunt_id=?""".format(TBL_HUNTING)
        cur.execute(sql, (hunt_status, hunt_run_at, hunt_chat_id, hunt_id,))
        con.commit()
    except Exception as ex:
        logger.warning(str(ex))
        return False
    finally:
        cur.close()
        con.close()
    return True


def vt_hunting_set_last_run(hunt_chat_id, hunt_id, hunt_last_run):
    """ SET Last run time of Hunting Job """
    try:
        con, cur = db_init(DB_PATH)
        sql = """ UPDATE {} SET hunt_last_run=? WHERE hunt_chat_id=? AND hunt_id=?""".format(TBL_HUNTING)
        cur.execute(sql, (hunt_last_run, hunt_chat_id, hunt_id,))
        con.commit()
    except Exception as ex:
        logger.warning(str(ex))
        return False
    finally:
        cur.close()
        con.close()
    return True


def vt_hunting_get_hunt_summary(hunt_chat_id, hunt_id='', to_dict=True):
    """ GET Summary info about Hunting Job """
    try:
        result = None
        con, cur = db_init(DB_PATH, to_dict=to_dict)
        if hunt_id:
            sql = """SELECT * FROM {} WHERE hunt_chat_id=? AND hunt_id=?""".format(TBL_HUNTING)
            cur.execute(sql, (hunt_chat_id, hunt_id,))
        else:
            sql = """SELECT * FROM {} WHERE hunt_chat_id=?""".format(TBL_HUNTING)
            cur.execute(sql, (hunt_chat_id,))
        result = cur.fetchall()
    except Exception as ex:
        logger.warning(str(ex))
    finally:
        cur.close()
        con.close()
    return result


def vt_hunting_get_hunt_content(hunt_chat_id, to_dict=False, is_hash=False, is_query=False, is_url=False):
    """ GET Hunt Content or Hunt source by User """
    try:
        result = None
        con, cur = db_init(DB_PATH, to_dict=to_dict)
        sql = """SELECT hunt_content, hunt_source FROM {} WHERE hunt_chat_id=? AND hunt_type=?""".format(TBL_HUNTING)
        if is_hash:
            cur.execute(sql, (hunt_chat_id, 'hash',))
        if is_query:
            cur.execute(sql, (hunt_chat_id, 'query',))
        if is_url:
            cur.execute(sql, (hunt_chat_id, 'url',))
        result = cur.fetchall()
    except Exception as ex:
        logger.warning(str(ex))
    finally:
        cur.close()
        con.close()
    return result


def vt_hunting_logs_get_summary(hunt_chat_id, hunt_id='', to_dict=True):
    """ GET Summary info from VTHuntingLogs """
    try:
        result = None
        con, cur = db_init(DB_PATH, to_dict=to_dict)
        if hunt_id:
            sql = """SELECT * FROM {} WHERE hunt_chat_id=? AND hunt_id=?""".format(TBL_HUNTING_LOGS)
            cur.execute(sql, (hunt_chat_id, hunt_id,))
        else:
            sql = """SELECT * FROM {} WHERE hunt_chat_id=?""".format(TBL_HUNTING_LOGS)
            cur.execute(sql, (hunt_chat_id,))
        result = cur.fetchall()
    except Exception as ex:
        logger.warning(str(ex))
    finally:
        cur.close()
        con.close()
    return result


def vt_hunting_logs_set_content(hunt_chat_id, hunt_id, hunt_content, hunt_last_update=''):
    """ Update hunt content for VTHuntingLogs """
    try:
        con, cur = db_init(DB_PATH)
        item = (hunt_id, hunt_chat_id, hunt_content, hunt_last_update, hunt_content)
        sql = """INSERT INTO {} (hunt_id, hunt_chat_id, hunt_content, hunt_last_update)
                 VALUES (?, ?, ?, ?)
                 ON CONFLICT(hunt_id) DO UPDATE SET hunt_content=?
        """.format(TBL_HUNTING_LOGS)
        cur.execute(sql, item)
        con.commit()
    except Exception as ex:
        logger.warning(str(ex))
        return False
    finally:
        cur.close()
        con.close()
    return True


def vip_member_logs_post(data: dict):
    """ Member POST logs to Database """
    try:
        con, cur = db_init(DB_PATH)
        create_time = int(datetime_to_unix(datetime.now()))
        item = (create_time, data['member_chat_id'], data['member_username'], data['member_key'], data['admin_chat_id'],
                data['member_logs_status'], data['member_logs'])
        sql = """INSERT INTO {} (create_time, member_chat_id, member_username, member_key, admin_chat_id, member_logs_status, member_logs)
                 VALUES (?, ?, ?, ?, ?, ?, ?)
                 """.format(TBL_VIP_MEMBER_LOGS)
        cur.execute(sql, item)
        con.commit()
    except Exception as ex:
        logger.warning(str(ex))
        return False
    finally:
        cur.close()
        con.close()
    return True


def vip_member_logs_get(admin_chat_id, member_username='', to_dict=True, limit=20):
    """ Admin GET Logs of Member """
    try:
        result = None
        con, cur = db_init(DB_PATH, to_dict=to_dict)
        if member_username:
            sql = """SELECT create_time, member_username, member_logs_status, member_logs
                     FROM {}
                     WHERE admin_chat_id=? AND member_username=?
                     ORDER BY create_time DESC
                     LIMIT ?""".format(TBL_VIP_MEMBER_LOGS)
            cur.execute(sql, (admin_chat_id, member_username, limit,))
        else:
            sql = """SELECT create_time, member_username, member_logs_status, member_logs
                     FROM {}
                     WHERE admin_chat_id=?
                     ORDER BY create_time DESC
                     LIMIT ?""".format(TBL_VIP_MEMBER_LOGS)
            cur.execute(sql, (admin_chat_id, limit,))
        result = cur.fetchall()
    except Exception as ex:
        logger.warning(str(ex))
        return None
    finally:
        cur.close()
        con.close()
    return result


def vip_member_get_private_keys(member_chat_id, member_key, to_dict=True):
    """ Member GET private/admin_key of Admin """
    try:
        result = None
        con, cur = db_init(DB_PATH, to_dict=to_dict)
        sql = """SELECT * FROM {} WHERE member_chat_id=? AND member_key=?""".format(TBL_VIP_MEMBER)
        cur.execute(sql, (member_chat_id, member_key,))
        result = cur.fetchall()
    except Exception as ex:
        logger.warning(str(ex))
    finally:
        cur.close()
        con.close()
    return result


def vip_member_check_exist(member_chat_id, member_key, admin_chat_id, to_dict=False):
    """ Admin GET available Member """
    try:
        result = None
        con, cur = db_init(DB_PATH, to_dict=to_dict)
        sql = """SELECT * FROM {} WHERE member_chat_id=? AND member_key=? AND admin_chat_id=?""".format(TBL_VIP_MEMBER)
        cur.execute(sql, (member_chat_id, member_key, admin_chat_id,))
        result = cur.fetchall()
    except Exception as ex:
        logger.warning(str(ex))
    finally:
        cur.close()
        con.close()
    return result


def vip_member_get_all(admin_chat_id, to_dict=True):
    """ GET all vip User managed by a Admin """
    try:
        result = None
        con, cur = db_init(DB_PATH, to_dict=to_dict)
        sql = """SELECT * FROM {} WHERE admin_chat_id=?""".format(TBL_VIP_MEMBER)
        cur.execute(sql, (admin_chat_id,))
        result = cur.fetchall()
    except Exception as ex:
        logger.warning(str(ex))
    finally:
        cur.close()
        con.close()
    return result


def vip_member_increment_query(member_chat_id, admin_key, member_key):
    """ Increment the number of queries by one """
    try:
        con, cur = db_init(DB_PATH)
        sql = """UPDATE {}
                 SET member_query_used=member_query_used+?
                 WHERE member_chat_id=? AND admin_key=? AND member_key=?""".format(TBL_VIP_MEMBER)
        cur.execute(sql, (1, member_chat_id, admin_key, member_key,))
        con.commit()
    except Exception as ex:
        logger.warning(str(ex))
        return False
    finally:
        cur.close()
        con.close()
    return True


def vip_member_add_by_days(member: dict):
    """ ADD new User by number of days """
    try:
        con, cur = db_init(DB_PATH)
        item = (member['member_key'], member['member_chat_id'], member['member_username'], member['member_start_time'],
                member['member_end_time'], member['member_is_query'], member['admin_key'], member['admin_username'],
                member['admin_chat_id'])
        sql = """INSERT INTO {} (member_key, member_chat_id, member_username, member_start_time, member_end_time, member_is_query, admin_key, admin_username, admin_chat_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""".format(TBL_VIP_MEMBER)
        cur.execute(sql, item)
        con.commit()
    except Exception as ex:
        logger.warning(str(ex))
        return False
    finally:
        cur.close()
        con.close()
    return True


def vip_member_add_by_requests(member: dict):
    """ ADD new User by number of requests/queries """
    try:
        con, cur = db_init(DB_PATH)
        item = (member['member_key'], member['member_chat_id'], member['member_username'], member['member_query_used'],
                member['member_query_allowed'], member['member_is_query'], member['admin_key'],
                member['admin_username'], member['admin_chat_id'])
        sql = """INSERT INTO {} (member_key, member_chat_id, member_username, member_query_used, member_query_allowed, member_is_query, admin_key, admin_username, admin_chat_id)
                 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""".format(TBL_VIP_MEMBER)
        cur.execute(sql, item)
        con.commit()
    except Exception as ex:
        logger.warning(str(ex))
        return False
    finally:
        cur.close()
        con.close()
    return True


def vip_member_renew(member_key, admin_chat_id, member_chat_id, new_number, member_is_query=False):
    """ RENEW VIP license for Member """
    try:
        con, cur = db_init(DB_PATH)
        if member_is_query:
            member_query_allowed = new_number
            sql = """UPDATE {}
                     SET member_query_allowed=?
                     WHERE member_chat_id=? AND member_key=? AND admin_chat_id=?
            """.format(TBL_VIP_MEMBER)
            cur.execute(sql, (member_query_allowed, member_chat_id, member_key, admin_chat_id,))
        else:
            member_end_time = new_number
            sql = """UPDATE {}
                     SET member_end_time=?
                     WHERE member_chat_id=? AND member_key=? AND admin_chat_id=?
            """.format(TBL_VIP_MEMBER)
            cur.execute(sql, (member_end_time, member_chat_id, member_key, admin_chat_id,))
        con.commit()
    except Exception as ex:
        logger.warning(str(ex))
        return False
    finally:
        cur.close()
        con.close()
    return True


def vip_member_del_key(member_chat_id, member_key, admin_chat_id):
    """ DELETE a User managed by a Admin"""
    try:
        con, cur = db_init(DB_PATH)
        sql = """DELETE FROM {} WHERE member_chat_id=? AND member_key=? AND admin_chat_id=?""".format(TBL_VIP_MEMBER)
        cur.execute(sql, (member_chat_id, member_key, admin_chat_id,))
        con.commit()
    except Exception as ex:
        logger.warning(str(ex))
        return False
    finally:
        cur.close()
        con.close()
    return True


def sd_users_search_key(chat_id, to_dict=True):
    """ Search SD Key by User """
    try:
        result = None
        con, cur = db_init(DB_PATH, to_dict=to_dict)
        sql = """SELECT * FROM {} WHERE chat_id=?""".format(TBL_SD_USER)
        cur.execute(sql, (chat_id,))
        result = cur.fetchall()
    except Exception as ex:
        logger.warning(str(ex))
    finally:
        cur.close()
        con.close()
    return result


def sd_users_del_key(chat_id):
    """ DELETE a SD Key by User """
    try:
        con, cur = db_init(DB_PATH)
        sql = """DELETE FROM {} WHERE chat_id=?""".format(TBL_SD_USER)
        cur.execute(sql, (chat_id,))
        con.commit()
    except Exception as ex:
        logger.warning(str(ex))
        return False
    finally:
        cur.close()
        con.close()
    return True


def sd_users_add_key(sd_key: dict):
    """ ADD new SD Key """
    try:
        con, cur = db_init(DB_PATH)
        item = (sd_key['shodan_key'], sd_key['chat_id'], sd_key['username'])
        sql = """INSERT INTO {}(shodan_key, chat_id, username) VALUES(?, ?, ?)""".format(TBL_SD_USER)
        cur.execute(sql, item)
        con.commit()
    except Exception as ex:
        logger.warning(str(ex))
        return False
    finally:
        cur.close()
        con.close()
    return True


def vt_users_search_one_key(chat_id, api_key, to_dict=False):
    """ SEARCH one api_key from User"""
    try:
        result = None
        con, cur = db_init(DB_PATH, to_dict=to_dict)
        sql = """SELECT * FROM {} WHERE chat_id=? AND api_key=?""".format(TBL_VT_USER)
        cur.execute(sql, (chat_id, api_key,))
        result = cur.fetchall()
    except Exception as ex:
        logger.warning(str(ex))
    finally:
        cur.close()
        con.close()
    return result


def vt_users_search_multi_key(chat_id):
    """ SEARCH multiple api_key from User """
    try:
        result = None
        con, cur = db_init(DB_PATH, to_dict=True)
        sql = """SELECT api_key, chat_id, username, is_private, is_enable FROM {} WHERE chat_id=?""".format(TBL_VT_USER)
        cur.execute(sql, (chat_id,))
        result = cur.fetchall()
    except Exception as ex:
        logger.warning(str(ex))
    finally:
        cur.close()
        con.close()
    return result


def vt_users_add_key(key: dict):
    """ ADD new api_key of user to db """
    try:
        con, cur = db_init(DB_PATH)
        item = (key["api_key"], key["chat_id"], key["username"], key["is_private"], key["is_enable"])
        sql = """INSERT INTO {} (api_key, chat_id, username, is_private, is_enable)
                 VALUES(?, ?, ?, ?, ?)""".format(TBL_VT_USER)
        cur.execute(sql, item)
        con.commit()
    except Exception as ex:
        logger.warning(str(ex))
        return False
    finally:
        cur.close()
        con.close()
    return True


def vt_users_del_one_key(chat_id, api_key):
    """ DELETE one key of User """
    try:
        con, cur = db_init(DB_PATH)
        sql = """DELETE FROM {} WHERE chat_id=? AND api_key=?""".format(TBL_VT_USER)
        cur.execute(sql, (chat_id, api_key,))
        con.commit()
    except Exception as ex:
        logger.warning(str(ex))
        return False
    finally:
        cur.close()
        con.close()
    return True


def vt_users_del_multi_key(chat_id):
    """ DELETE multiple api_key of User """
    try:
        con, cur = db_init(DB_PATH)
        sql = """DELETE FROM {} WHERE chat_id=?""".format(TBL_VT_USER)
        cur.execute(sql, (chat_id,))
        con.commit()
    except Exception as ex:
        logger.warning(str(ex))
        return False
    finally:
        cur.close()
        con.close()
    return True


def vt_users_set_enabled_key(chat_id, api_key):
    """ SET Enabled/Disabled api_key of User """
    try:
        con, cur = db_init(DB_PATH)
        sql_enable = """UPDATE {} SET is_enable=? WHERE chat_id=? AND api_key=?""".format(TBL_VT_USER)
        cur.execute(sql_enable, (True, chat_id, api_key,))
        con.commit()
        sql_disable = """UPDATE {} SET is_enable=? WHERE chat_id=? AND api_key!=?""".format(TBL_VT_USER)
        cur.execute(sql_disable, (False, chat_id, api_key,))
        con.commit()
    except Exception as ex:
        logger.warning(str(ex))
        return False
    finally:
        cur.close()
        con.close()
    return True


def vt_users_get_enabled_key(chat_id):
    """ GET enabled api_key of User """
    try:
        result = None
        con, cur = db_init(DB_PATH, to_dict=True)
        sql = """SELECT * FROM {} WHERE chat_id=? AND is_enable=?""".format(TBL_VT_USER)
        cur.execute(sql, (chat_id, True,))
        result = cur.fetchone()
    except Exception as ex:
        logger.warning(str(ex))
    finally:
        cur.close()
        con.close()
    return result
