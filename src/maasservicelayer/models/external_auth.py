# Copyright 2024-2026 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from enum import IntEnum
from typing import Any, ClassVar

from pydantic import BaseModel, Field

from maasservicelayer.models.base import (
    generate_builder,
    MaasTimestampedBaseModel,
)


class ProviderMetadata(BaseModel):
    # These fields are based on the OpenID Connect Discovery specification (https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
    # We only include the fields that are relevant for our use case, but additional fields can be added as needed.
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str | None = None
    introspection_endpoint: str | None = None
    revocation_endpoint: str | None = None
    jwks_uri: str


class AccessTokenType(IntEnum):
    JWT = 0
    OPAQUE = 1


class ProviderVendorType(IntEnum):
    GENERIC = 0
    ENTRAID = 1
    AUTH0 = 2
    KEYCLOAK = 3


class OIDCGroupSyncConfig(BaseModel):
    """Sync MAAS user groups from an ID token or userinfo claim on login.

    With an empty `group_map`, a claim value maps to the MAAS group of the
    same name and every MAAS group is managed. Otherwise only the groups in
    `group_map` values are managed, and the rest are left untouched.
    """

    CONFIG_KEY: ClassVar[str] = "group_sync"

    enabled: bool = False
    claim: str = Field(default="groups", min_length=1)
    group_map: dict[str, str] = Field(default_factory=dict)

    @classmethod
    def from_provider_config(
        cls, config: dict[str, Any] | None
    ) -> "OIDCGroupSyncConfig":
        return cls.model_validate((config or {}).get(cls.CONFIG_KEY, {}))


@generate_builder()
class OAuthProvider(MaasTimestampedBaseModel):
    issuer_url: str
    name: str
    vendor: ProviderVendorType
    client_id: str
    client_secret: str
    redirect_uri: str
    token_type: AccessTokenType
    scopes: str
    enabled: bool
    metadata: ProviderMetadata
    config: dict[str, Any] | None = None

    @property
    def group_sync(self) -> OIDCGroupSyncConfig:
        return OIDCGroupSyncConfig.from_provider_config(self.config)
