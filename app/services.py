from __future__ import annotations

from dataclasses import dataclass

from .approvals import ApprovalService
from .carddav import CardDAVClient
from .config import Settings
from .devices import DeviceService
from .events import EventBus
from .opnsense import AccessController, OPNsenseClient
from .ratelimit import LimitPolicy, LoginLimiter


@dataclass
class Services:
    settings: Settings
    opn: OPNsenseClient
    access: AccessController
    carddav: CardDAVClient
    bus: EventBus
    approvals: ApprovalService
    devices: DeviceService
    limiter: LoginLimiter

    async def aclose(self) -> None:
        await self.opn.aclose()
        await self.carddav.aclose()


def build_services(st: Settings, *, opn_transport=None, carddav_transport=None) -> Services:
    opn = OPNsenseClient(st.opnsense_url, st.opnsense_key, st.opnsense_secret, verify=st.opnsense_verify,
                         zone_id=st.opnsense_zone_id, alias_name=st.opnsense_alias_name, transport=opn_transport)
    access = AccessController(opn, use_zone=st.uses_zone, use_alias=st.uses_alias)
    carddav = CardDAVClient(st.carddav_url, st.carddav_user, st.carddav_password, region=st.phone_default_region,
                            verify=st.carddav_verify_tls, cache_seconds=st.contact_cache_seconds,
                            min_refresh_seconds=st.contact_min_refresh_seconds, transport=carddav_transport)
    bus = EventBus()
    return Services(
        settings=st, opn=opn, access=access, carddav=carddav, bus=bus,
        approvals=ApprovalService(bus, carddav, ttl_seconds=st.approval_ttl_seconds,
                                  cooldown_seconds=st.approval_cooldown_seconds),
        devices=DeviceService(bus, access),
        limiter=LoginLimiter(LimitPolicy(st.login_max_failures, st.login_window_seconds,
                                         st.login_backoff_base_seconds, st.login_backoff_max_seconds)),
    )
