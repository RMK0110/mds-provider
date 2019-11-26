class BoltClientCredentials(AuthorizationToken):
    """
    Represents an authenticated session via the Bolt authentication scheme,
    documented at:
    <no URL>
    Currently, your config needs:
    * email
    * password
    * mds_api_url
    * token_url
    """

    def __init__(self, provider):
        """
        Acquires the provider token for Bolt before establishing a session.
        """
        payload = {"email": provider.email, "password": provider.password}
        r = requests.post(provider.token_url, params=payload)
        provider.token = r.json()["token"]

        AuthorizationToken.__init__(self, provider)

    @classmethod
    def can_auth(cls, provider):
        """
        Returns True if this auth type can be used for the provider.
        """
        return all(
            [
                provider.provider_name.lower() == "bolt",
                hasattr(provider, "email"),
                hasattr(provider, "password"),
                hasattr(provider, "token_url"),
            ]
        )
