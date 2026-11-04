"""样本环境变量规则的布尔判定；调用方只保留变量名。"""
import re


HINTS = {"token", "tokens", "secret", "secrets", "password", "passwd", "passphrase", "pat",
         "apikey", "credential", "credentials", "auth", "authorization"}
EXCLUDED_SUFFIXES = {
    "accountid", "clientid", "fileversion", "assemblyversion", "integrity", "cachedemail", "approved",
    "publishable", "envkey", "selectedtype", "inherits", "discovery", "authorizationserver", "servername",
    "serverurl", "needsauth", "firsttokendate", "claudecodefirsttokendate", "clientsecretbasic",
}


def key_hint(name):
    words = re.sub(r"([a-z])([A-Z])", r"\1 \2", name)
    words = re.sub(r"([A-Z])([A-Z][a-z])", r"\1 \2", words)
    words = re.findall(r"[a-z][a-z0-9]*", words.lower())
    if any("".join(words[i:]) in EXCLUDED_SUFFIXES for i in range(len(words))) or "public" in name.lower():
        return False
    return (bool(re.search(r"api_?key|access_?key|client_?secret|private_?key", name.lower()))
            or bool(HINTS.intersection(words)) or (len(words) > 1 and words[-1] == "key"))


def token_detected(value, rules):
    if len(value) < 8:
        return False
    if re.search(r"-----BEGIN [^\r\n]{0,100}PRIVATE KEY-----", value):
        return True
    if re.search(r"(?<![A-Za-z0-9_])sk-[A-Za-z0-9_~.-]{20,197}T3BlbkFJ[A-Za-z0-9_~.-]{20}(?![A-Za-z0-9_])", value):
        return True
    if re.search(r"[A-Za-z0-9_~.-]{3}[0-9]Q~[A-Za-z0-9_~.]{31,34}(?![A-Za-z0-9_~.])", value):
        return True
    for rule in rules:
        parts = []
        for step in rule["steps"]:
            if step[0] == "lit":
                literals = step[1] if isinstance(step[1], list) else [step[1]]
                parts.append("(?:" + "|".join(re.escape(s) for s in literals) + ")")
            else:
                maximum = "" if step[3] == -1 else str(step[3])
                # 样本逐步消费字符且不回溯；Python 3.11 的占有量词保持此行为。
                parts.append("[" + step[1] + "]{" + str(step[2]) + "," + maximum + "}+")
        expression = "".join(parts)
        if rule.get("boundary", True):
            expression = r"(?<![A-Za-z0-9_])" + expression + r"(?![A-Za-z0-9_])"
        if re.search(expression, value):
            return True
    return False


def environment_candidate(name, value, rules):
    if name.upper() in {"PATH", "PWD", "OLDPWD", "TEMP", "TMP", "_"} or not isinstance(value, str):
        return False
    if re.match(r"^[A-Za-z]:[/\\]|^[/\\]", value):
        return False
    return token_detected(value, rules) or (key_hint(name) and len(value) >= 8 and not re.search(r"\s", value))
