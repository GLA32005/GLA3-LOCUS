import logging
from rich.logging import RichHandler
from rich.console import Console
from rich.theme import Theme

custom_theme = Theme({
    "logging.time": "#555555",
    "logging.level.info": "#c9d1d9",
    "logging.level.warning": "#e3a117",
    "logging.level.error": "bold #ff5f5f",
    "logging.level.critical": "bold #ff5f5f",
    # 覆盖 Rich 默认的高饱和度语法高亮，使用代码编辑器 (VS Code Dark+) 同款配色
    "repr.number": "#b5cea8",          # 浅绿 (Dark+ 数字)
    "repr.string": "#ce9178",          # 橘粉 (Dark+ 字符串)
    "repr.ipv4": "#ce9178",            # 橘粉 (同字符串)
    "repr.uuid": "#ce9178",            # 橘粉 (同字符串)
    "repr.url": "underline #ce9178",   # 橘粉下划线
    "repr.bool_true": "#569cd6",       # 纯蓝 (Dark+ 关键字/布尔值)
    "repr.bool_false": "#569cd6",      # 纯蓝
    "repr.none": "#569cd6",            # 纯蓝
    "repr.path": "#ce9178",
    "repr.filename": "#ce9178",
    "repr.attrib_name": "#9cdcfe",     # 浅蓝 (Dark+ 变量/属性)
    "repr.attrib_value": "#ce9178",
    "repr.tag_name": "#569cd6",        # 纯蓝
    "repr.call": "#dcdcaa",            # 淡黄 (Dark+ 函数调用)
})

console = Console(theme=custom_theme)

class LocusFormatter(logging.Formatter):
    def format(self, record):
        # 统一格式化 message
        msg = record.getMessage()
        
        # 替换 SUCCESS / STRONG 高亮
        if "STRONG" in msg:
            msg = msg.replace("STRONG", "[#3fb950]STRONG[/]")
        if "SUCCESS" in msg:
            msg = msg.replace("SUCCESS", "[#3fb950]SUCCESS[/]")
        if "stall=" in msg:
            import re
            msg = re.sub(r'(stall=\d+)', r'[#00d4aa]\1[/]', msg)
        if "target=" in msg:
            import re
            msg = re.sub(r'(target=[\w\.]+)', r'[#00d4aa]\1[/]', msg)
        if "conf=" in msg:
            import re
            msg = re.sub(r'(conf=[\d\.]+)', r'[#00d4aa]\1[/]', msg)

        if record.levelno >= logging.ERROR:
            msg_color = "bold #ff5f5f"
        elif record.levelno >= logging.WARNING:
            msg_color = "#a8852a"
        else:
            msg_color = "#c9d1d9"

        # 如果 msg 里已经有了富文本标签，直接包在里面可能会有嵌套冲突，
        # 但 rich 通常能优雅处理。
        # 这里把原本的 logging.Formatter 的工作做掉：
        formatted_name = f"[#6b8cba]{record.name:<22}[/]"
        return f"{formatted_name} [#555555]│[/] [{msg_color}]{msg}[/]"

def setup_logging(log_level=logging.INFO):
    import os
    from logging.handlers import TimedRotatingFileHandler

    console_handler = RichHandler(
        console=console,
        rich_tracebacks=True,
        show_path=False,
        markup=True
    )
    console_handler.setFormatter(LocusFormatter())
    
    log_dir = os.path.expanduser("~/.locus/logs")
    os.makedirs(log_dir, exist_ok=True)
    file_handler = TimedRotatingFileHandler(
        filename=os.path.join(log_dir, "locus.log"),
        when="midnight",
        interval=1,
        backupCount=7,
        encoding="utf-8"
    )
    plain_formatter = logging.Formatter(
        fmt="[%(asctime)s] %(levelname)-8s %(name)-22s │ %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(plain_formatter)

    # 获取根 logger 并设置
    root = logging.getLogger()
    root.setLevel(log_level)
    
    # 移除已有的 handlers 避免重复
    for h in root.handlers[:]:
        root.removeHandler(h)
        
    root.addHandler(console_handler)
    root.addHandler(file_handler)
    
    # 静音第三方库
    for noisy in ("httpx", "httpcore", "urllib3", "asyncio", "uvicorn.access", "neo4j", "neo4j.notifications"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

