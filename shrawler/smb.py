"""Small reusable SMB authentication and connection primitives."""

from dataclasses import dataclass
from getpass import getpass
from typing import Any, Callable, Optional, Tuple, cast

from impacket.examples import utils as impacket_utils
from impacket.smbconnection import SMBConnection

parse_target = cast(
    Callable[[str], Tuple[str, str, str, str]],
    impacket_utils.parse_target,  # pyright: ignore[reportUnknownMemberType]
)


@dataclass(frozen=True)
class SMBAuth:
    domain: str
    username: str
    password: str
    lmhash: str
    nthash: str
    kerberos: bool
    aes_key: Optional[str]
    target_host: str
    kdc_host: Optional[str]


def create_smb_auth(
    auth_spec: str,
    hashes: Optional[str],
    no_pass: bool,
    kerberos: bool,
    aes_key: Optional[str],
) -> SMBAuth:
    """Normalize CLI authentication inputs into one immutable value."""
    domain, username, password, host = parse_target(auth_spec)
    lmhash = nthash = ""
    if hashes is not None:
        try:
            lmhash, nthash = hashes.split(":", 1)
        except ValueError as exc:
            raise ValueError("--hashes must use LMHASH:NTHASH format") from exc
    if not password and username and hashes is None and not no_pass and aes_key is None:
        password = getpass("Password:")
    return SMBAuth(
        domain=domain,
        username=username,
        password=password,
        lmhash=lmhash,
        nthash=nthash,
        kerberos=kerberos or bool(aes_key),
        aes_key=aes_key,
        target_host=host,
        kdc_host=host or None,
    )


def connect_smb(
    host: str,
    auth: SMBAuth,
    client_factory: Callable[..., Any] = SMBConnection,
) -> Any:
    client = client_factory(host, host, sess_port=445)
    client.enableDFSSupport = True
    try:
        if auth.kerberos:
            client.kerberosLogin(
                auth.username,
                auth.password,
                auth.domain,
                auth.lmhash,
                auth.nthash,
                auth.aes_key,
                auth.kdc_host,
            )
        else:
            client.login(
                auth.username, auth.password, auth.domain, auth.lmhash, auth.nthash
            )
    except Exception:
        close_smb(client)
        raise
    return client


def close_smb(client: Any) -> None:
    try:
        client.logoff()
    except Exception:
        pass
