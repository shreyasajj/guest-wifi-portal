"""Runtime configuration, read from environment variables (see .env.example)."""
from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


def _split(value: str) -> list[str]:
    return [p.strip() for p in value.replace("\n", ",").split(",") if p.strip()]


def _networks(value: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    return [ipaddress.ip_network(p, strict=False) for p in _split(value)]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- general ---
    site_name: str = "HomeNet"
    secret_key: str = "change-me"
    database_url: str = "sqlite:////data/portal.db"
    public_admin_url: str = ""  # e.g. https://wifi-admin.home.example (used for the OIDC redirect URI)
    public_guest_url: str = ""  # e.g. https://wifi.home.example (used by the RFC 8908 captive portal API)
    session_cookie_secure: bool = True
    log_level: str = "INFO"

    # --- OPNsense ---
    opnsense_url: str = "https://192.168.1.1"
    opnsense_key: str = ""
    opnsense_secret: str = ""
    opnsense_verify_tls: str = "true"  # "true", "false" or a path to a CA bundle
    opnsense_zone_id: int = 0
    guest_interfaces: str = ""  # comma list; matched against ARP `intf` and lease `if`/`if_name`
    access_mode: Literal["zone", "alias", "both"] = "both"
    opnsense_alias_name: str = "GUEST_AUTH_MACS"
    dhcp_backend: Literal["kea", "dnsmasq", "isc", "none"] = "kea"
    dhcp_recent_seconds: int = 600

    # --- Nextcloud CardDAV ---
    carddav_url: str = ""  # https://cloud.example/remote.php/dav/addressbooks/users/<user>/<book>/
    carddav_user: str = ""
    carddav_password: str = ""
    carddav_verify_tls: bool = True
    contact_cache_seconds: int = 300
    contact_min_refresh_seconds: int = 15
    phone_default_region: str = "US"

    # --- network trust ---
    trusted_proxies: str = ""  # CIDRs of reverse proxies allowed to set X-Forwarded-For
    admin_allowed_networks: str = "192.168.1.0/24"

    # --- admin auth ---
    admin_username: str = "admin"
    admin_password_hash: str = ""  # argon2 hash, generate with: python -m app.hashpw
    oidc_issuer: str = ""  # e.g. https://auth.example.com (Authelia)
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_scopes: str = "openid profile email groups"
    oidc_allowed_groups: str = ""  # comma list; empty = any authenticated user
    oidc_label: str = "Authelia"

    # --- API (Home Assistant) ---
    api_tokens: str = ""

    # --- approvals ---
    approval_ttl_seconds: int = 600
    approval_cooldown_seconds: int = 20

    # --- login rate limit ---
    login_max_failures: int = 5
    login_window_seconds: int = 900
    login_backoff_base_seconds: int = 60
    login_backoff_max_seconds: int = 3600

    # --- workers ---
    workers_enabled: bool = True
    presence_poll_seconds: int = 30
    away_grace_seconds: int = 300
    reconcile_seconds: int = 60
    approval_expiry_check_seconds: int = 5
    mac_expiry_days: int = 30
    event_retention_days: int = 14

    @property
    def trusted_proxy_networks(self):
        return _networks(self.trusted_proxies)

    @property
    def admin_networks(self):
        return _networks(self.admin_allowed_networks)

    @property
    def guest_interface_list(self) -> list[str]:
        return [i.lower() for i in _split(self.guest_interfaces)]

    @property
    def api_token_list(self) -> list[str]:
        return _split(self.api_tokens)

    @property
    def oidc_group_list(self) -> list[str]:
        return _split(self.oidc_allowed_groups)

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id)

    @property
    def opnsense_verify(self) -> bool | str:
        v = self.opnsense_verify_tls.strip()
        if v.lower() in ("true", "1", "yes"):
            return True
        if v.lower() in ("false", "0", "no"):
            return False
        return v

    @property
    def uses_zone(self) -> bool:
        return self.access_mode in ("zone", "both")

    @property
    def uses_alias(self) -> bool:
        return self.access_mode in ("alias", "both")


@lru_cache
def get_settings() -> Settings:
    return Settings()
