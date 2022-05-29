#!/usr/bin/env python

from telegram.ext import Updater, CommandHandler
from telegram.ext import MessageHandler, Filters

from tlgconfig.telegram import TLG_BOT_TOKEN
from tlgbot.tlg_urls import urls_handler
from tlgbot.tlg_files import files_handler
from tlgbot.tlg_comment import comment_handler
from tlgbot.tlg_domains import domains_handler
from tlgbot.tlg_enterprise import enterprise_handler
from tlgbot.tlg_ip_address import ip_address_handler
from tlgbot.tlg_vip_member import vip_member_handler
from tlgbot.tlg_key_manager import key_manager_handler
from tlgbot.tlg_shodan import sd_handler
from tlgbot.tlg_hunting import hunting_handler
from tlgbot.tlg_utils import help_command, echo_message, error_handler


def main():
    """
    Python Telegram Bot.
    Usage: Press Ctrl-C on the command line or send a signal to the process to stop the bot.
    Ref: https://www.codementor.io/@karandeepbatra/part-1-how-to-create-a-telegram-bot-in-python-in-under-10-minutes-19yfdv4wrq
    """

    # Create the Updater and pass it your bot's token.
    # Make sure to set use_context=True to use the new context based callbacks
    # Post version 12 this will no longer be necessary
    updater = Updater(TLG_BOT_TOKEN, use_context=True)
    # updater = Updater(TLG_BOT_TOKEN, use_context=True, request_kwargs={'read_timeout': 20, 'connect_timeout': 20})

    # Get the dispatcher to register handlers
    dp = updater.dispatcher

    # on different commands - answer in Telegram
    command_handler = {
        'help': help_command,
        'key': key_manager_handler,
        'etp': enterprise_handler,
        'file': files_handler,
        'url': urls_handler,
        'domain': domains_handler,
        'ip': ip_address_handler,
        'cmt': comment_handler,
        'vip': vip_member_handler,
        'shodan': sd_handler,
        'hunt': hunting_handler
    }
    for command, handler in command_handler.items():
        dp.add_handler(CommandHandler(command, handler, pass_job_queue=True))

    # on non-command i.e message - echo the message on Telegram
    dp.add_handler(MessageHandler(Filters.text, echo_message))

    # log all errors
    dp.add_error_handler(error_handler)

    # Start the Bot
    updater.start_polling()

    # Run the bot until you press Ctrl-C or the process receives SIGINT,
    # SIGTERM or SIGABRT. This should be used most of the time, since
    # start_polling() is non-blocking and will stop the bot gracefully.
    updater.idle()


if __name__ == '__main__':
    main()
