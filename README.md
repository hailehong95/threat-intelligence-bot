# Threat Intelligence Bot

## 1. Build and run

```bash
$ git clone https://github.com/hailehong95/Threat-Intelligence-Bot.git
$ cd Threat-Intelligence-Bot
```
### Cấu hình Telegram Bot

Sử dụng [BotFather](https://telegram.me/BotFather) để tạo Bot, sau khi tạo xong sẽ nhận được một chuỗi `Access Token`

Mở tệp `.env` sau đó thay thế `<YOUR_TELEGRAM_BOT_TOKEN>` bằng `Access Token` vừa nhận được. Ví dụ:

```bash
TLG_BOT_TOKEN=0123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
Sau khi cấu hình xong có thể tùy chọn một trong hai cách cài đặt là dùng __docker__ hoặc __docker-compose__

### Build và Run với Docker

```bash
$ docker build -t tibot:1.0.1 .
$ docker run --env-file .env -d tibot:1.0.1
```
Kiểm tra:

```bash
$ docker ps -a
$ docker logs -f <container_id>
```

### Build và run với Docker Compose

```bash
$ docker-compose up -d
```

Kiểm tra:
```bash
$ docker-compose ps -a
$ docker-compose logs -f
```

## 2. Planned Integration

- VirusTotal Intelligence - https://developers.virustotal.com/v3.0/reference
- Shodan Internet Intelligence Platform - https://developer.shodan.io/
- MISP Threat Sharing - https://www.misp-project.org/
- Python Telegram Bot's- https://python-telegram-bot.readthedocs.io/

## 3. References

- vtapi3 - https://github.com/drobotun/virustotalapi3
- API Scripts and client libraries - https://support.virustotal.com/hc/en-us/articles/360006819798-API-Scripts-and-client-libraries
