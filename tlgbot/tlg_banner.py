def tlg_bot_banner(update, context):
    markdown_text = "`{0} BẢNG ĐIỀU KHIỂN {0}`\n".format(':' * 16)
    markdown_text += "`/key help         : Quản lý Keys`\n"
    markdown_text += "`/file help        : Tìm kiếm Files`\n"
    markdown_text += "`/url help         : Tìm kiếm URL`\n"
    markdown_text += "`/domain help      : Tìm kiếm Domains`\n"
    markdown_text += "`/ip help          : Tìm kiếm IP Address`\n"
    markdown_text += "`/cmt help         : VT Comments`\n"
    markdown_text += "`/vip help         : VIP Member`\n"
    markdown_text += "`/etp help         : VT Enterprise`\n"
    markdown_text += "`/hunt help        : VT Hunting`\n"
    markdown_text += "`/shodan help      : Shodan Search Engine`\n"
    markdown_text += "`Threat intelligence Bot v1.0.1`\n"
    update.message.reply_text(markdown_text, parse_mode='MarkdownV2')


def key_manager_banner(update, context):
    markdown_text = "`{0} QUẢN LÝ KHÓA {0}`\n".format(':' * 16)
    markdown_text += "`/key add <key>         : Thêm VT key`\n"
    markdown_text += "`/key del [key]         : Xóa VT key`\n"
    markdown_text += "`/key dump [key]        : Xuất VT key`\n"
    markdown_text += "`/key enable <key>      : Bật/Tắt VT key`\n"
    markdown_text += "`/key export            : Export VT key ra tệp tin`\n"
    update.message.reply_text(markdown_text, parse_mode='MarkdownV2')


def comment_banner(update, context):
    markdown_text = "`{0} COMMENT FEED TỪ VIRUSTOTAL {0}`\n".format(':' * 10)
    markdown_text += "`/cmt feed              : Feed comments từ VT`\n"
    markdown_text += "`/cmt del <cmt_ip>      : Delete comment trên VT`\n"
    update.message.reply_text(markdown_text, parse_mode='MarkdownV2')


def domains_banner(update, context):
    markdown_text = "`{0} TÌM KIẾM TÊN MIỀN {0}`\n".format(':' * 16)
    markdown_text += "`/domain rp <domain>         : Get domain report từ VT`\n"
    markdown_text += "`/domain gcmt <domain>       : Get domain comments từ VT`\n"
    markdown_text += "`/domain pcmt <hash>         : Put domain comment lên VT`\n"
    markdown_text += "`/domain gvote <hash>        : Get domain vote từ VT`\n"
    markdown_text += "`/domain pvote <hash>        : Put domain vote lên VT`\n"
    markdown_text += "`/domain rel <hash>          : Get domain relationship từ VT`\n"
    update.message.reply_text(markdown_text, parse_mode='MarkdownV2')


def enterprise_banner(update, context):
    markdown_text = "`{0} VIRUSTOTAL ENTERPRISE {0}`\n".format(':' * 16)
    markdown_text += "`/etp info [key]          : Check VT key`\n"
    markdown_text += "`/etp dl <hash/url>       : Get sample từ VT`\n"
    markdown_text += "`/etp si <query>          : Search Intelligence`\n"
    markdown_text += "`/etp czip <hash1 hash2>  : Create '.zip' files từ VT`\n"
    markdown_text += "`/etp szip <zip_id>       : Check '.zip' files status từ VT`\n"
    markdown_text += "`/etp dzip <zip_id>       : Get '.zip' files từ VT`\n"
    update.message.reply_text(markdown_text, parse_mode='MarkdownV2')


def files_banner(update, context):
    markdown_text = "`{0} TÌM KIẾM TỆP TIN {0}`\n".format(':' * 16)
    markdown_text += "`/file upload              : Put file lên VT`\n"
    markdown_text += "`/file real                : Re-analysis file trên VT`\n"
    markdown_text += "`/file rp <hash>           : Get File report từ VT`\n"
    markdown_text += "`/file gcmt <hash>         : Get file comments từ VT`\n"
    markdown_text += "`/file pcmt <hash>         : Put file comments lên VT`\n"
    markdown_text += "`/file gvote <hash>        : Get file votes từ VT`\n"
    markdown_text += "`/file pvote <hash>        : Put file vote lên VT`\n"
    markdown_text += "`/file rel <hash>          : Get file relationship từ VT`\n"
    markdown_text += "`/file bhv <hash>          : Get file behaviour từ VT`\n"
    markdown_text += "`/file html <hash>         : Get file report (html) từ VT`\n"
    markdown_text += "`/file sigma <hash>        : Get Sigma Rules từ VT`\n"
    markdown_text += "`/file yara <hash>         : Get YARA Rules từ VT`\n"
    update.message.reply_text(markdown_text, parse_mode='MarkdownV2')


def ip_address_banner(update, context):
    markdown_text = "`{0} TÌM KIẾM ĐỊA CHỈ IP {0}`\n".format(':' * 16)
    markdown_text += "`/ip rp <ip>           : Get IP report từ VT`\n"
    markdown_text += "`/ip gcmt <ip>         : Get IP comments VT`\n"
    markdown_text += "`/ip pcmt <ip>         : Put IP comment lên VT`\n"
    markdown_text += "`/ip gvote <ip>        : Get IP vote từ VT`\n"
    markdown_text += "`/ip pvote <ip>        : Put IP vote lên VT`\n"
    markdown_text += "`/ip rel <ip>          : Get IP relationship từ VT`\n"
    update.message.reply_text(markdown_text, parse_mode='MarkdownV2')


def urls_banner(update, context):
    markdown_text = "`{0} TÌM KIẾM URL {0}`\n".format(':' * 16)
    markdown_text += "`/url sub <url>           : Put URL lên VT`\n"
    markdown_text += "`/url real <url>          : Re-analysis URL trên VT`\n"
    markdown_text += "`/url rp <url>            : Get URL report từ VT`\n"
    markdown_text += "`/url gcmt <hash>         : Get URL comments từ VT`\n"
    markdown_text += "`/url pcmt <hash>         : Put URL comment lên VT`\n"
    markdown_text += "`/url gvote <hash>        : Get URL vote từ VT`\n"
    markdown_text += "`/url pvote <hash>        : Put URL vote lên VT`\n"
    markdown_text += "`/url rel <hash>          : Get URL relationship từ VT`\n"
    update.message.reply_text(markdown_text, parse_mode='MarkdownV2')


# Banner for private key admin
def vip_admin_banner(update, context):
    markdown_text = "`{0} VIP MEMBER {0}`\n".format(':' * 16)
    markdown_text += "`/vip day <number> <key> <chat_id>  : Cấp VIP theo ngày`\n"
    markdown_text += "`/vip req <number> <key> <chat_id>  : Cấp VIP theo lượt`\n"
    markdown_text += "`/vip ren <number> <key> <chat_id>  : Gia hạn thêm VIP`\n"
    markdown_text += "`/vip del <key> <chat_id>           : Xóa VIP Member`\n"
    markdown_text += "`/vip dump [key]                    : Kiểm tra VIP Member`\n"
    markdown_text += "`/vip log [username]                : Lịch sử VIP Member`\n"
    update.message.reply_text(markdown_text, parse_mode='MarkdownV2')


# Banner for public key member
def vip_member_banner(update, context):
    markdown_text = "`{0} VIP MEMBER {0}`\n".format(':' * 16)
    markdown_text += "`/vip dl <hash>           : Get sample từ VT`\n"
    markdown_text += "`/vip si <query>          : Search Intelligence`\n"
    update.message.reply_text(markdown_text, parse_mode='MarkdownV2')


# Banner for shodan search engine
def shodan_banner(update, context):
    markdown_text = "`{0} SHODAN SEARCH ENGINE {0}`\n".format(':' * 16)
    markdown_text += "`/shodan add <key>              : Add Shodan key`\n"
    markdown_text += "`/shodan del                    : Delete Shodan key`\n"
    markdown_text += "`/shodan info [key]             : Check Shodan key`\n"
    markdown_text += "`/shodan ip <ip>                : Search IP trên Shodan`\n"
    markdown_text += "`/shodan search <query>         : Shodan Search Query`\n"
    markdown_text += "`/shodan sub <domain>           : Search subdomain trên Shodan`\n"
    markdown_text += "`/shodan dti <domain1,domain2>  : Domains to IP`\n"
    markdown_text += "`/shodan itd <ip1,ip2>          : IP to Domains`\n"
    update.message.reply_text(markdown_text, parse_mode='MarkdownV2')


# Banner for VirusTotal Hunting
def hunting_banner(update, context):
    markdown_text = "`{0} VIRUSTOTAL HUNTING {0}`\n".format(':' * 16)
    markdown_text += "`/hunt hash <hashes>              : Create Hunting Job Hash`\n"
    markdown_text += "`/hunt update <hunt_id> <hashes>  : Update Hunting Job Hash`\n"
    markdown_text += "`/hunt url <url>                  : Create Hunting Job URL`\n"
    markdown_text += "`/hunt update <hunt_id>           : Update Hunting Job URL`\n"
    markdown_text += "`/hunt si <query>                 : Create Hunting Job Query`\n"
    markdown_text += "`/hunt stime <hunt_id> <times>    : Schedule time cho Hunting Job`\n"
    markdown_text += "`/hunt dump [hunt_id]             : Export Hunting Job info`\n"
    markdown_text += "`/hunt export                     : Export all hash`\n"
    markdown_text += "`/hunt del <hunt_id>              : Delete một Hunting Job`\n"
    markdown_text += "`/hunt log <hunt_id>              : Hunting Job history`\n"
    markdown_text += "`/hunt start                      : Starting Hunting Job`\n"
    markdown_text += "`/hunt status                     : Status Hunting Job`\n"
    markdown_text += "`/hunt stop                       : Stopping Hunting Job`\n"
    update.message.reply_text(markdown_text, parse_mode='MarkdownV2')
