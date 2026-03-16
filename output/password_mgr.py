import secrets

_password: str = ""


def generate_password() -> str:
    global _password
    _password = secrets.token_urlsafe(16)
    return _password


def get_password() -> str:
    if not _password:
        return generate_password()
    return _password
