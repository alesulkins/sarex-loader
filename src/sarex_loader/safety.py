"""Fail-closed execution policy; this stage has no execution override."""


class ValidationError(ValueError):
    """Only fixed, developer-owned messages may be supplied to this exception."""


def require_offline_dry_run(
    *, dry_run: bool, network_enabled: bool, write_enabled: bool
) -> None:
    # Identity checks deliberately reject 0/1 and strings masquerading as booleans.
    if dry_run is not True or network_enabled is not False or write_enabled is not False:
        raise ValidationError(
            "Разрешены только dry_run=true, network_enabled=false, write_enabled=false."
        )