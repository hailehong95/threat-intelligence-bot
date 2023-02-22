# Threat Intelligence Bot

For details about using the bot, please refer to the [Docs - Threat Intelligence Bot (Vietnamese)](./docs/README.md)

## 1. Create Telegram bot and configuration

- Chat with **[BotFather](https://telegram.me/BotFather)** to create Bot, you will receive a `Access Token` string
- Clone bot source code:

    ```bash
    $ git clone https://github.com/hailehong95/threat-intelligence-bot.git
    $ cd threat-intelligence-bot
    ```

- Bot configuration: edit `.env` file and replace `<YOUR_TELEGRAM_BOT_TOKEN>` with your `Access Token`, example:

    ```bash
    TLG_BOT_TOKEN=0123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    ```

## 2. Deploying the Telegram bot

After the configuration is completed, you can use **docker** or **docker-compose** for bot deployment

### 2.1. Build and Run with Docker

```bash
$ docker build -t tibot:1.0.1 .
$ docker run --env-file .env -d tibot:1.0.1
```

To verified:

```bash
$ docker ps -a
$ docker logs -f <container_id>
```

### 2.2. Build and run with Docker Compose

```bash
$ docker-compose up -d
```

To verified:
```bash
$ docker-compose ps -a
$ docker-compose logs -f
```

## 3. References

- Python Telegram Bot's: https://python-telegram-bot.readthedocs.io/
- VirusTotal Intelligence: https://developers.virustotal.com/v3.0/reference
- API Scripts and client libraries: https://support.virustotal.com/hc/en-us/articles/360006819798-API-Scripts-and-client-libraries
- vtapi3: https://github.com/drobotun/virustotalapi3
- Shodan: https://developer.shodan.io/

## 4. Note

- This project for learning purposes
- Do not use in production environment
- It probably very buggy!
